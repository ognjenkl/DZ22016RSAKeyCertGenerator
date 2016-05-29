import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class RsaKeyCertGenerator {

	Properties props = null;
	String csrPath;
	String certPath;
	String caCertPath;
	String caKeyPath;
	String p12FilePath;
	int passLength;
	Scanner sc;
	
	public RsaKeyCertGenerator() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
			Security.addProvider(new BouncyCastleProvider());
		
		props = new Properties();
		File file = new File("resources/config.properties");
		InputStream in = null;
		sc = new Scanner(System.in);
		
		try {	
			if(file.exists()){
				in = new FileInputStream(file);
				props.load(in);
				
				csrPath = props.getProperty("csrPath");
				certPath = props.getProperty("certPath");
				caCertPath = props.getProperty("caCertPath");
				caKeyPath = props.getProperty("caKeyPath");
				p12FilePath = props.getProperty("p12FilePath");
				passLength = Integer.parseInt(props.getProperty("passLength"));
			}
			else
				System.out.println("Ne postoji config file!");
				
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		RsaKeyCertGenerator rsaKeyCertGenerator = new RsaKeyCertGenerator();

		rsaKeyCertGenerator.doTheThing();
		
	
	}

	public void doTheThing() {
		try {

			//int keyLength = 1024;
			int keyLength = getKeyLengthFromConslole();

			KeyPair keyPair = genRsaKeys(keyLength);

			// certificate request creation
			JcaPKCS10CertificationRequest jcaCsr = getJcaCertificateRequest(keyPair);
			
			//write csr to file
			if (isValidCertificateRequest(jcaCsr, keyPair.getPublic())) {
				FileWriter fileWriter = new FileWriter(csrPath);
				JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
				pemWriter.writeObject(jcaCsr);
				pemWriter.flush();
				pemWriter.close();
			} else
				System.out.println("Certificate Request is NOT created");

			// import ca certificate
			File fileCaCert = new File(caCertPath);
			if (fileCaCert.exists()) {
				InputStream in = new FileInputStream(fileCaCert);
				CertificateFactory factory = CertificateFactory.getInstance("X.509");
				X509Certificate issuerCert = (X509Certificate) factory.generateCertificate(in);

				// crate certificate builder
				X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
						issuerCert,
						new BigInteger(getSerialHexRandom(8), 16), 
						new Date(System.currentTimeMillis()),
						new Date(System.currentTimeMillis() + 3L * 365L * 24L * 60L * 60L * 1000L), 
						jcaCsr.getSubject(),
						jcaCsr.getPublicKey());

				// read pem private key
				File fileCaPrivateKey = new File(caKeyPath);
				BufferedReader bufferedReader = new BufferedReader(new FileReader(fileCaPrivateKey));
				PEMParser pemParser = new PEMParser(bufferedReader);
				PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
				KeyPair caKeyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
				pemParser.close();

				// sign certificate
				JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
				ContentSigner contentSigner = contentSignerBuilder.build(caKeyPair.getPrivate());
				X509CertificateHolder certHolder = certBuilder.build(contentSigner);
				CertificateFactory certFactory = CertificateFactory.getInstance("X.509",
						BouncyCastleProvider.PROVIDER_NAME);
				Certificate certStructure = certHolder.toASN1Structure();
				InputStream inCert = new ByteArrayInputStream(certStructure.getEncoded());
				// signed certificate
				X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inCert);

				// save cert as file
				File fileCert = new File(certPath);
				FileWriter fileWriter = new FileWriter(fileCert);
				JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
				pemWriter.writeObject(certificate);
				pemWriter.flush();
				pemWriter.close();

				// create .p12 (PKCS12) file
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(null, null);
				keyStore.setCertificateEntry("cert", certificate);
				String passwd = genPassRandom(passLength);
				X509Certificate[] chain = new X509Certificate[1];
				chain[0] = certificate;
				keyStore.setKeyEntry("key", keyPair.getPrivate(), passwd.toCharArray(), chain);
				keyStore.store(new FileOutputStream(p12FilePath), passwd.toCharArray());

				System.out.println("\nAll done!");
				System.out.println("PKCS12 password: ");
				System.out.println(passwd);
			}

		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			sc.close();
		}
	}

	/**
	 * 
	 * Inputs key bit length from console.
	 * 
	 * @return
	 */
	public int getKeyLengthFromConslole() {
		String consoleInput = "";
		int keyLength = 0;
		do {
			System.out.print("Unesite duzinu RSA kljuca u bitima (1024 ili 2048): ");
			if (sc.hasNext())
				consoleInput = sc.nextLine();
			if (consoleInput.equals("1024") || consoleInput.equals("2048"))
				keyLength = Integer.parseInt(consoleInput);
			else {
				keyLength = 0;
				System.out.println("Neispravna duzina kljuca!");
			}
		} while (keyLength == 0);

		return keyLength;
	}

	/**
	 * 
	 * Generates RSA private and public keys with keyBitLength bit length.
	 * 
	 * @param keyBitLength
	 * @return
	 */
	public KeyPair genRsaKeys(int keyBitLength) {
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
			keyPairGenerator.initialize(keyBitLength);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyPairGenerator.genKeyPair();

	}

	/**
	 * Input Distinguished Names (DN) for certificate generation
	 * 
	 * @return
	 */
	public X500Name getDNFromConsole() {
		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		
		String line = "";

		do {
			System.out.println("Unesite Country: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() != 2);
		nameBuilder.addRDN(BCStyle.CN, line.toUpperCase());

		do {
			System.out.println("Unesite State: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() < 1);
		nameBuilder.addRDN(BCStyle.ST, line);

		do {
			System.out.println("Unesite Locality: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() < 1);
		nameBuilder.addRDN(BCStyle.L, line);

		do {
			System.out.println("Unesite Organisation: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() < 1);
		nameBuilder.addRDN(BCStyle.O, line);

		do {
			System.out.println("Unesite Organisation Unit: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() < 1);
		nameBuilder.addRDN(BCStyle.OU, line);

		do {
			System.out.println("Unesite Comon Name: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() < 1);
		nameBuilder.addRDN(BCStyle.CN, line);

		do {
			System.out.println("Unesite eMail: ");
			if (sc.hasNext())
				line = sc.nextLine();
		} while (line.length() < 1);
		nameBuilder.addRDN(BCStyle.E, line);

		return nameBuilder.build();
	}

	/**
	 * 
	 * Validates csr signature.
	 * 
	 * @param csr
	 * @param publicKey
	 * @return
	 */
	public boolean isValidCertificateRequest(PKCS10CertificationRequest csr, PublicKey publicKey) {
		try {
			if (csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey)))
				return true;
			else
				return false;
		} catch (OperatorCreationException | PKCSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

	}

	/**
	 * Retruns string of serilaLength characters
	 * 
	 * @param serialLength
	 *            number of characters in returned string
	 * @return hexadecimal string of serilaLength length
	 */
	public String getSerialHexRandom(int serialLength) {
		Random rand = new Random();
		String result = Integer.toHexString(rand.nextInt(0x8));
		for (int i = 1; i < serialLength; i++)
			result += Integer.toHexString(rand.nextInt(0x10));
		//System.out.println(result);
		return result;
	}

	/**
	 * Generates random pass of passLenth characters length.
	 * 
	 * @param passLength
	 * @return
	 */
	public String genPassRandom(int passLength) {
		String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%*.?";
		StringBuffer sBuffer = new StringBuffer();
		SecureRandom rand = new SecureRandom();
		while (sBuffer.length() < passLength)
			sBuffer.append(alphabet.charAt(rand.nextInt(alphabet.length())));

		return sBuffer.toString();
	}

	public JcaPKCS10CertificationRequest getJcaCertificateRequest(KeyPair keyPair) {
		JcaPKCS10CertificationRequest jcaCsr = null;
		try {
			PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(getDNFromConsole(),
					keyPair.getPublic());
			// JcaPKCS10CertificationRequestBuilder csrBuilder = new
			// JcaPKCS10CertificationRequestBuilder(getDNFromConsole(),keyPair.getPublic());
			JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
			ContentSigner contentSigner;

			contentSigner = contentSignerBuilder.build(keyPair.getPrivate());

			PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);
			// JcaPKCS10CertificationRequest csr =
			// (JcaPKCS10CertificationRequest) csrBuilder.build(contentSigner);
			// final certificate request
			jcaCsr = new JcaPKCS10CertificationRequest(csr.getEncoded());
		} catch (OperatorCreationException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return jcaCsr;
	}
}
