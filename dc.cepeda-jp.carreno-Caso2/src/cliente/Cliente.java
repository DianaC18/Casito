package cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import seguridad.Certificado;
import seguridad.Cifrado;

public class Cliente {
	
	//-----------------------------------------------------
	// Constantes protocolo
	//-----------------------------------------------------
	public final static String HOLA = "HOLA";
	public final static String OK = "OK";
	public final static String ALGS = "AES";
	public final static String ALGA = "RSA";
	public final static String ALGHMAC = "HMACSHA1";
	public final static String ERROR = "ERROR";

	private static final String IP = "localhost";
	private static Certificado certificado;
	private static X509Certificate certificadoServidor;

	public static void main(String[] args) throws IOException {

		certificado = new Certificado();

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		try	{
			socket = new Socket(IP, 8084);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));		
		}
		catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}

		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

		try{
			comenzar(lector, escritor, socket.getInputStream(), socket.getOutputStream());			
		}
		catch (Exception e){
			e.printStackTrace();
		}
		finally {
			System.out.println("Conexión terminada");
			stdIn.close();
			escritor.close();
			lector.close();		
			// cierre el socket y la entrada estándar
			socket.close();
		}	
	}	

	public static void comenzar( BufferedReader pLector, PrintWriter pEscritor, InputStream pInput, OutputStream pOutput ) throws Exception
	{
		String inputLine, outputLine;
		String certificadoString = "";
		int estado = 0;

		pEscritor.println(HOLA);
		System.out.println("Cliente: " + HOLA);

		boolean finalizo = false;

		while (!finalizo && (inputLine = pLector.readLine()) != null) 
		{
			switch( estado ) {
			case 0:
				
				System.out.println("Servidor: " + inputLine);
				
				if (inputLine.equalsIgnoreCase(OK)) 
				{
					outputLine = "ALGORITMOS:"+ALGS+":"+ALGA+":"+ALGHMAC;
					estado++;
				} 
				else 
				{
					outputLine = ERROR;
					estado = -1;
				}
				
				pEscritor.println(outputLine);
				System.out.println("Cliente: " + outputLine);
				break;
			case 1:
				System.out.println("Servidor: " + inputLine);
				
				if(inputLine.equalsIgnoreCase(OK))
				{
					byte[] bytes = certificado.createBytes(new Date(), new Date(), ALGA, 512, "SHA1withRSA");
					certificadoString = toByteArrayHexa(bytes);
										
					pEscritor.println(certificadoString);
					System.out.println("Cliente: Certificado del cliente");	
					estado++;
					
				}
				else
				{
					estado = -1;
				}
				break;
			case 2:
				
					String sCertificadoServidor = inputLine;
					byte[] certificadoBytes = new byte['�'];
					certificadoBytes = toByteArray(sCertificadoServidor);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(certificadoBytes);
					certificadoServidor =  (X509Certificate) cf.generateCertificate(in);
					System.out.println("Servidor: Certificado del servidor");
				    
					SecretKey sk = createSymmetricKey(ALGS);
					
					String encodedKey = Base64.getEncoder().encodeToString(sk.getEncoded());
				
					byte[] bytess = toByteArray(encodedKey);
					
					byte [] llaveCifrada=Cifrado.cifrar(certificadoServidor.getPublicKey(), bytess, ALGA);
					
					String llaveCif=toByteArrayHexa(llaveCifrada);
					outputLine=llaveCif;
					pEscritor.println(outputLine);
					
					System.out.println("Cliente: "+ outputLine);
					
					
					estado++;
					
				break;
			
			case 3:
				System.out.println("Cliente: " + inputLine);
				if(inputLine.equalsIgnoreCase(OK))
				{
					//Cifrar consulta	
					String sConsulta = new String(""+ (int) Math.floor(Math.random()*1000));
					byte[] consulta = sConsulta.getBytes();
					byte[] cifrarConsulta = Cifrado.cifrarLS(certificado.getLlaveSimetrica(), consulta);
					String consultaCifrada = toByteArrayHexa(cifrarConsulta);
					outputLine = consultaCifrada;
					pEscritor.println(outputLine);
					System.out.println("Cliente: " + outputLine);

					//Hash
					byte[] hash = Cifrado.getKeyDigest(consulta, certificado.getLlaveSimetrica());
					String hashConsulta = toByteArrayHexa(hash);
					outputLine = hashConsulta;
					pEscritor.println(outputLine);
					System.out.println("Cliente: " + outputLine);
					
					estado++;
					
				}
				else
				{
					outputLine = "";
					pEscritor.println(outputLine);
					estado = -1;
				}
				break;
				
//			case 5:
//				System.out.println(inputLine+"wiiiiiiiiiiii");
//				if (inputLine.equalsIgnoreCase(OK)) 
//				{
//					outputLine = "ALGORITMOS:"+ALGS+":"+ALGA+":"+ALGHMAC;
//					estado++;
//				} 
//				else 
//				{
//					outputLine = ERROR;
//					estado = -1;
//				}
//				
//				pEscritor.println(outputLine);
//				System.out.println("Cliente: " + outputLine);
//				
//				
//				break;
			default:
				estado = -1;
				break;
			}
		}		
	}

	private static byte[] toByteArray(String cert) {
		return DatatypeConverter.parseHexBinary(cert);
	}

	private static String toByteArrayHexa(byte[] byteArray) {

		String out = "";
		for (int i = 0; i < byteArray.length; i++) {
			if ((byteArray[i] & 0xff) <= 0xf) {
				out += "0";
			}
			out += Integer.toHexString(byteArray[i] & 0xff).toUpperCase();
		}

		return out;
	}
	

	/**
	 * Generates a symmetric key according to the specified algorithm
	 * @param algorithm
	 * @return the key
	 * @throws NoSuchAlgorithmException
	 */
	private static SecretKey createSymmetricKey(String algorithm) throws NoSuchAlgorithmException{
		KeyGenerator gen = KeyGenerator.getInstance(algorithm);
		return gen.generateKey();
	}
	

}
