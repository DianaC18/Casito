package seguridad;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import cliente.Cliente;
import srvcifIC201820.Seg;

public class Certificado {
	
	private final static String ALGORITMO = "RSA";
	private KeyPair own;
	private java.security.cert.X509Certificate server;
	private SecretKey llaveSimetrica;

	public Certificado()
	{
		own = null;
		server = null;
		llaveSimetrica = null;
	}

	private KeyPair createKeyPair(String encryptionType, int byteCount) throws NoSuchProviderException, NoSuchAlgorithmException
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ALGORITMO, "BC");
		kpGen.initialize(1024);
		return kpGen.generateKeyPair();
	}

	private String convertCertificateToPEM(java.security.cert.X509Certificate cert) throws IOException 
	{
		StringWriter certStringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(certStringWriter);
		pemWriter.writeObject(cert);
		pemWriter.close();
		return certStringWriter.toString();
	}

	public String create(Date start, Date expiry, String encryptionType, int bitCount, String signatureAlgoritm) throws Exception
	{		
		KeyPair keyPair = createKeyPair(encryptionType, bitCount);
		own = keyPair;
		return convertCertificateToPEM(Seg.gc(own));
	}
	
	public byte[] createBytes(Date start, Date expiry, String encryptionType, int bitCount, String signatureAlgoritm) throws Exception
	{		
		KeyPair keyPair = createKeyPair(encryptionType, bitCount);
		own = keyPair;
		return Seg.gc(own).getEncoded();
	}

	public PublicKey getOwnPublicKey()
	{
		if(own != null)
			return own.getPublic();
		else
			return null;
	}

	public PrivateKey getOwnPrivateKey()
	{
		if(own != null)		
			return own.getPrivate();
		else
			return null;

	}

	public PublicKey getServerPublicKey()
	{
		if(server != null)
			return server.getPublicKey();
		else
			return null;
	}

	public void setLlaveSimetrica(byte[] llave)
	{
		SecretKeySpec sk = new SecretKeySpec(llave, Cliente.ALGS);
		llaveSimetrica = sk;
	}

	public SecretKey getLlaveSimetrica()
	{
		return llaveSimetrica;
	}
}
