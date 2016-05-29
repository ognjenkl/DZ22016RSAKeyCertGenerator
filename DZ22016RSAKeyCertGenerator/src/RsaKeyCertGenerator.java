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
import java.security.KeyStoreException;
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
import java.util.logging.LoggingMXBean;

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

	Scanner sc = null;
	
	public RsaKeyCertGenerator() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
			Security.addProvider(new BouncyCastleProvider());
		
		sc = new Scanner(System.in);
				
		
	}

	public static void main(String[] args) {
		RsaKeyCertGenerator rsaKeyCertGenerator = new RsaKeyCertGenerator();

		rsaKeyCertGenerator.doBusinessLogic();
		
	
	}

	/**
	 * Does business logic of generating RSA Keys, creating CSR, signing certificate, 
	 * packaging private key and signed certificate into PKCS12 (.p12) file and
	 * writes .p12 password on console
	 * 
	 */
	public void doBusinessLogic() {
		Properties props = null;
		String csrPath = null;
		String certPath = null;
		String caCertPath = null;
		String caKeyPath = null;
		String p12FilePath = null;
		int passLength = 0;
		long yearsNumber = 0L;
		
		
		try {

			props = new Properties();
			File file = new File("resources/config.properties");
			InputStream in = null;
			
			
			if(file.exists()){
				in = new FileInputStream(file);
				props.load(in);
				
				csrPath = props.getProperty("csrPath");
				certPath = props.getProperty("certPath");
				caCertPath = props.getProperty("caCertPath");
				caKeyPath = props.getProperty("caKeyPath");
				p12FilePath = props.getProperty("p12FilePath");
				passLength = Integer.parseInt(props.getProperty("passLength"));
				yearsNumber = Long.parseLong(props.getProperty("yearsNumber"));
			}
			else
				System.out.println("Ne postoji config file!");
				
			//int keyLength = 1024;
			int keyLength = getKeyLengthFromConslole();

			KeyPair keyPair = genRsaKeys(keyLength);

			//create Distinguished Names (dn)
			X500Name distinguishedNames = getDNFromConsole();
			
			// certificate request creation
			JcaPKCS10CertificationRequest jcaCsr = createJcaCertificateRequest(keyPair, distinguishedNames);
			
			//write csr to file
			writeCsrToFile(jcaCsr, keyPair, csrPath);

			// import ca certificate
			X509Certificate issuerCert = getCaCert(caCertPath);
			
			// read pem private key
			KeyPair caKeyPair = getCaKeyPair(caKeyPath);

			// sign certificate
			X509Certificate certificate = null;
			if(yearsNumber > 0)
				certificate = signCertificate(caKeyPair, issuerCert, jcaCsr, yearsNumber);
			
			// save cert as file
			writeCertToFile(certificate, certPath);

			// create .p12 (PKCS12) file
			//String passwd = createPKCS12File(certificate, keyPair, issuerCert, p12FilePath, passLength);
			String passwd = createPKCS12File(certificate, keyPair, p12FilePath, passLength);
			
			System.out.println("\nAll done!");
			System.out.println("PKCS12 password: ");
			System.out.println(passwd);


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
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public KeyPair genRsaKeys(int keyBitLength) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyPairGenerator.initialize(keyBitLength);
	
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
	 * Validates certificate request signature.
	 * 
	 * @param csr
	 * @param keyPair
	 * @return
	 * @throws PKCSException 
	 * @throws OperatorCreationException 
	 */
	public boolean isValidCertificateRequest(PKCS10CertificationRequest csr, KeyPair keyPair) throws OperatorCreationException, PKCSException {
		if (csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(keyPair.getPublic())))
			return true;
		else
			return false;
	}

	/**
	 * Returns string of serilaLength random characters
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
	 * Generates random pass of passLenth characters.
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

	/**
	 * Generates certificate request.
	 * 
	 * @param keyPair
	 * @return
	 * @throws OperatorCreationException
	 * @throws IOException
	 */
	public JcaPKCS10CertificationRequest createJcaCertificateRequest(KeyPair keyPair, X500Name dn) throws OperatorCreationException, IOException {
		PKCS10CertificationRequestBuilder csrBuilder = 
				new JcaPKCS10CertificationRequestBuilder(dn,keyPair.getPublic());
		JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());
		PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);
		return new JcaPKCS10CertificationRequest(csr.getEncoded());
	}
	
	/**
	 * Writes certificate request into file.
	 * 
	 * @param jcaCsr
	 * @param keyPair
	 * @param csrPath
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws PKCSException
	 */
	public void writeCsrToFile(JcaPKCS10CertificationRequest jcaCsr, KeyPair keyPair, String csrPath) throws IOException, OperatorCreationException, PKCSException{
		File filePath = new File(csrPath);
		if (isValidCertificateRequest(jcaCsr, keyPair)) {
			FileWriter fileWriter = new FileWriter(filePath);
			JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
			pemWriter.writeObject(jcaCsr);
			pemWriter.flush();
			pemWriter.close();
		} else
			System.out.println("Certificate Request is NOT created");
		
	}
	
	/**
	 * Imports CA Certificate.
	 * 
	 * @param path
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 */
	public X509Certificate getCaCert(String path) throws CertificateException, IOException{
		X509Certificate issuerCert = null;
		InputStream in = null;
		File fileCaCert = new File(path);
		
		if (fileCaCert.exists()) {
			in = new FileInputStream(fileCaCert);
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			issuerCert = (X509Certificate) factory.generateCertificate(in);
			in.close();
		} else
			System.out.println("Ther is no ca cert on path: " + path);
		
		return issuerCert;
	}
	
	/**
	 * Imports CA Key.
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public KeyPair getCaKeyPair(String path) throws IOException{
		File fileCaPrivateKey = new File(path);
		KeyPair caKeyPair = null;
		if(fileCaPrivateKey.exists()){
			BufferedReader bufferedReader = new BufferedReader(new FileReader(fileCaPrivateKey));
			PEMParser pemParser = new PEMParser(bufferedReader);
			PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
			caKeyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			pemParser.close();
		}
		else
			System.out.println("There is no CA Key on path: " + path );
		
		return caKeyPair;
	}
	
	/**
	 * Signs certificate request.
	 * 
	 * @param caKeyPair
	 * @param issuerCert
	 * @param jcaCsr
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 */
	public X509Certificate signCertificate(KeyPair caKeyPair, X509Certificate issuerCert, JcaPKCS10CertificationRequest jcaCsr, long yearsNumber) 
						throws 	InvalidKeyException, NoSuchAlgorithmException, OperatorCreationException, 
								CertificateException, NoSuchProviderException, IOException{

		X509Certificate certificate = null;
			
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
			issuerCert,
			new BigInteger(getSerialHexRandom(8), 16), 
			new Date(System.currentTimeMillis()),
			new Date(System.currentTimeMillis() + yearsNumber * 365L * 24L * 60L * 60L * 1000L), 
			jcaCsr.getSubject(),
			jcaCsr.getPublicKey());
		
		
		JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner contentSigner = contentSignerBuilder.build(caKeyPair.getPrivate());
		X509CertificateHolder certHolder = certBuilder.build(contentSigner);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509",
				BouncyCastleProvider.PROVIDER_NAME);
		Certificate certStructure = certHolder.toASN1Structure();
		InputStream inCert = new ByteArrayInputStream(certStructure.getEncoded());
		// signed certificate
		certificate = (X509Certificate) certFactory.generateCertificate(inCert);

		inCert.close();
		
		return certificate;
	}
	
	public void writeCertToFile(X509Certificate certificate, String certPath) throws IOException{
		File fileCert = new File(certPath);
		FileWriter fileWriter = new FileWriter(fileCert);
		JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
		pemWriter.writeObject(certificate);
		pemWriter.flush();
		pemWriter.close();
	}
	
	/**
	 * 
	 * 
	 * @param certificate
	 * @param keyPair
	 * @param p12FilePath
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	//public String createPKCS12File(X509Certificate certificate, KeyPair keyPair, X509Certificate issuerCert, String p12FilePath, int passLength)
	public String createPKCS12File(X509Certificate certificate, KeyPair keyPair, String p12FilePath, int passLength)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		
		String passwd = null;
		//FileOutputStream out = new FileOutputStream(p12FilePath);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		//won't work without this line
		keyStore.load(null, null);
		keyStore.setCertificateEntry("cert", certificate);
		
		//password for .p12 and private key encription
		if(passLength > 5)
			passwd = genPassRandom(passLength);
		else{
			System.out.println("Password length must be greater than 5");
			return "";
		}
		
		X509Certificate[] chain = new X509Certificate[1];
		chain[0] = certificate;
		//chain[1] = issuerCert;
		keyStore.setKeyEntry("key", keyPair.getPrivate(), passwd.toCharArray(), chain);
		//keyStore.store(out, passwd.toCharArray());
		//out.close();
		keyStore.store(new FileOutputStream(p12FilePath), passwd.toCharArray());
		
		return passwd;
	}
	
	
}
