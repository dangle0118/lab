
import java.io.*;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.BodyPart;
import javax.mail.MessagingException;

import org.krakenapps.mime.*;
import org.krakenapps.pcap.decoder.ftp.FtpDecoder;
import java.io.IOException;
import java.io.InputStream;

import org.krakenapps.pcap.decoder.telnet.*;
import org.krakenapps.pcap.decoder.smtp.*;
import org.krakenapps.pcap.decoder.ftp.*;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.http.HttpProcessor;
import org.krakenapps.pcap.decoder.http.HttpRequest;
import org.krakenapps.pcap.decoder.http.HttpResponse;
import org.krakenapps.pcap.decoder.msn.*;
import org.krakenapps.pcap.util.PcapFileRunner;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.FileExtractor;
import org.krakenapps.pcap.Protocol;
import java.net.InetAddress;

public class lab {
	private static final String SECRET_FILE = "secretrendezvous.docx";
	
	
	public static void main(String[] args) throws IOException {
		PcapFileRunner runner = new PcapFileRunner(new File("evidence03.pcap"));
		HttpDecoder http = new HttpDecoder();
		FtpDecoder ftp = new FtpDecoder(runner.getTcpDecoder().getProtocolMapper());
		MsnDecoder msn = new MsnDecoder();
		SmtpDecoder smtp = new SmtpDecoder();
		TelnetDecoder telnet = new TelnetDecoder();
		
		String http_file = "http_file.txt";
		String smtp_file = "smtp_file.txt";
		String ftp_file = "ftp_file.txt";
		String telnet_file = "telnet_file.txt";
		
		FileWriter out_http = new FileWriter(http_file);
		FileWriter out_smtp = new FileWriter(smtp_file);
		
		
		telnet.register(new TelnetProcessor(){
			@Override
			public void onClientCommand(TelnetCommand command, TelnetOption option, byte[] data){
				
				if (command.hasOption() && data.length > 0)
				{
					System.out.print("Client Command option: ");
					for (int i = 0; i < data.length; ++i)
					{
						System.out.print(option.parse(data[i])+" ");						
					}
					System.out.println();
				}
			}
			@Override
			public void onServerCommand(TelnetCommand command, TelnetOption option, byte[] data){
				if (command.hasOption() && data.length > 0 )
				{
					System.out.print("Server Command option: ");
					for (int i = 0; i < data.length; ++i)
					{
						System.out.print(option.parse(data[i])+" ");						
					}
					System.out.println();
				}
			}
			@Override
			public void onClientAnsiControl(AnsiMode mode, TelnetCommand command, int[] arguments){
				
			}
			@Override
			public void onServerAnsiControl(AnsiMode mode, TelnetCommand command, int[] arguments){
				
			}
			@Override
			public void onClientData(String text){
				System.out.print(text);
			}
			@Override
			public void onServerData(String text){
				System.out.print(text);
			}
			@Override
			public void onClientTitle(String title){
				System.out.println(title);
			}
			@Override
			public void onServerTitle(String title){
				System.out.println(title);
			}
		});
		
		smtp.register(new SmtpProcessor() {
			
			public void output(String command, String parameter)
			{
				String smtp_file = "smtp_file.txt";
				try{
					FileWriter smtp_out = new FileWriter(smtp_file, true);
					
					if ( command.equals("MAIL"))
						{
							smtp_out.write(command + " " + parameter + "\r\n");		
							smtp_out.close();
						}
					
						if (command.equals("RCPT")) 
					{
						smtp_out.write(command + " " + parameter + "\r\n");
						smtp_out.close();
					}
									
				} catch( IOException e){
					e.printStackTrace();
				}
				
			}
			@Override
			public void onCommand(String command, String parameter) {
				
				output(command, parameter);	
			}

			@Override
			public void onReply(int code, String message) {
				//System.out.println(code + " " + message);
			}

			@Override
			public void onSend(MimeHeader header, SmtpData data) {
				BodyPart docx = getSecretDocStream(data.getMimeMessage() );
				if (docx == null)
					return;
				try{
					FileExtractor.extract(new File(SECRET_FILE), docx.getInputStream());
					System.out.println(SECRET_FILE + " is extracted.");
				}
					catch(IOException e){
					}
					catch(MessagingException e){
					}			
			
			}
			private BodyPart getSecretDocStream(MimeMessage message)
			{
				try{
					MimeMultipart part = (MimeMultipart) message.getContent();
					for (int i = 0; i < part.getCount(); i++)
					{
						BodyPart bodyPart = part.getBodyPart(i);
						String contentType = bodyPart.getContentType();
						if (contentType.contains(SECRET_FILE))
							return bodyPart;
					}			
				} catch (IOException e){
					e.printStackTrace();
				} catch (MessagingException e){
					e.printStackTrace();
				}
				return null;
			}
		});
		
		msn.register(new MsnProcessor(){
			@Override
			public void onChat(String account, String chat)
			{
				System.out.println(account + ": " + chat);
			}
		});
		
		ftp.register(new FtpProcessor(){
			@Override
			public void viewList(byte[] list)
			{
				System.out.println(new String(list));
			}
			
			@Override 
			public void onCommand(String command)
			{
				System.out.println(command);				
			}
			
			@Override
			public void onReply(String reply)
			{
				System.out.println(reply);
			}
			
			@Override
			public void onExtractFile(InputStream is, String fileName)
			{
				System.out.println("dumping" + fileName);
				File f = new File(fileName);
				try{
					FileExtractor.extract(f,is);
				} catch (IOException e){
					e.printStackTrace();
				}
			}
				
		}
		);
	
		http.register(new HttpProcessor() {
			public void onRequest(HttpRequest req, InetAddress ClientIp, InetAddress ServerIp) {
			}
			@Override
			public void onResponse(HttpRequest req, HttpResponse resp, InetAddress ClientIp, InetAddress ServerIp) {
		//		if ( req != null )
				{
				try {
					
						String[] tokens = req.getURL().toString().split("/");
						String fileName = tokens[tokens.length - 1];

			        // extract all .jpg files from http stream!	    
						if (fileName.endsWith(".jpg")) {
					InputStream is = resp.getMimeMessage().getInputStream();
					System.out.println("get file name: " + fileName);
					FileExtractor.extract(new File(fileName), is);
				}
			    } catch (IOException e) {
			    } catch (MessagingException e) {
			    }

			System.out.println("Client: " + ClientIp + "\nServer: " + ServerIp );
				System.out.println(req.getURL());
				}
				}
			
			@Override
			public void onMultipartData(Buffer buffer){}
		});

		
		runner.setTcpProcessor(Protocol.TELNET, telnet);
		runner.setTcpProcessor(Protocol.SMTP, smtp);
		runner.setTcpProcessor(Protocol.MSN, msn);
		runner.setTcpProcessor(Protocol.HTTP,  http);
		runner.setTcpProcessor(Protocol.FTP,  ftp);
		
		runner.run();
	}
	
	
	
	
}



