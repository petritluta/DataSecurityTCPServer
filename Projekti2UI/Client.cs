using System;
using System.Net;
using System.Net.Sockets;
using System.Xml;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Projekti2UI{

    class Client 
    {
        private Socket client;
        private RSACryptoServiceProvider rsa=new RSACryptoServiceProvider();
        
        private UserModel user=null;

        private DESCryptoServiceProvider  des = null;
        
        public Client()
        {

            try
            {
                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddr = ipHost.AddressList[0];
                IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 11111);
                client=new Socket(ipAddr.AddressFamily,SocketType.Stream,ProtocolType.Tcp);
                client.Connect(localEndPoint);
                sendMessage("CHello");      
                
                exe();

            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
            }
          
        }

        public string menu()
       {
            Console.WriteLine("Press 1 to login,2 to register,3 to add expenses,4 to list your expenses and 0 to quit");

            try{
                int choice= Convert.ToInt32(Console.ReadLine());
                switch(choice)
                {
                    case 1:
                        Console.WriteLine("Login with your credentials in the following syntax: Login <username> <password>");
                        return Console.ReadLine();
                    case 2:
                        Console.WriteLine("Register with your credentials in the following syntax: Register <username> <password>");
                        return Console.ReadLine();
                    case 3:
                        if(this.user == null)
                        {
                            Console.WriteLine("You need to be signed in");
                            return null;
                        }
                        Console.WriteLine("Add expenses to your account in the following syntax: Expense <name> <type> <value> <year> <month>");
                        string command= Console.ReadLine();
                        command+=" "+this.user.idGetSet;
                        return command;
                    case 4:
                        if(this.user == null)
                        {
                            Console.WriteLine("You need to be signed in");
                            return null;
                        }
                        else{
                            this.user.listExpenses();
                            return null;
                        }
                    case 0:
                        return "quit";
                    default:
                        throw new Exception("Invalid input");
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
           
       }

       public void shutdown()
       {
            client.Shutdown(SocketShutdown.Both);
            client.Close();
       }
        

        public void exe()
        {   
            string choice=menu();
            while(choice!="quit")
            {   
                if(choice!=null)
                    sendMessage(choice);
                choice=menu();
            }
            sendMessage("quit");
            shutdown();
        }


        public string decryptMessageClient(string message)
        {

            byte[] fullMsgData=Convert.FromBase64String(message);
            byte[] iv=new byte[8];
            Array.Copy(fullMsgData,iv,8);


            des.IV=iv;
            des.Mode=CipherMode.CBC;
                        
            byte[] encryptedMessage=new byte[fullMsgData.Length-iv.Length];
                        
                        
            Array.Copy(fullMsgData,iv.Length,encryptedMessage,0,fullMsgData.Length-iv.Length);

                        
            MemoryStream memoryStream=new MemoryStream();
            CryptoStream cryptoStream=new CryptoStream(memoryStream,des.CreateDecryptor(),CryptoStreamMode.Write);
            cryptoStream.Write(encryptedMessage,0,encryptedMessage.Length);
            cryptoStream.FlushFinalBlock();
            byte[] decryptedMsg=memoryStream.ToArray();

            string decryptedData=Encoding.ASCII.GetString(decryptedMsg);

            return decryptedData;
        }

      
    
        public void sendMessage(string message)
        {   

            try{
                if(message!="CHello")
                {

                
                    des=new DESCryptoServiceProvider();
                    des.GenerateIV();
                    des.GenerateKey();
                    byte[] iv=des.IV;
                    byte[] desKey=rsa.Encrypt(des.Key,false);
                    // Console.WriteLine("iv length="+iv.Length+" iv value="+Convert.ToBase64String(des.IV)+" deskey  length="+desKey.Length+"  des encrytpted="+Convert.ToBase64String(desKey)+" des decrypted="+Convert.ToBase64String(des.Key));
                    
                    des.Mode=CipherMode.CBC;
                    MemoryStream memoryStream=new MemoryStream();
                    CryptoStream cryptoStream=new CryptoStream(memoryStream,des.CreateEncryptor(),CryptoStreamMode.Write);
                    cryptoStream.Write(Encoding.ASCII.GetBytes(message),0,Encoding.ASCII.GetBytes(message).Length);
                    cryptoStream.FlushFinalBlock();
                    byte[] encryptedMsg=memoryStream.ToArray();
                    
                    // Console.WriteLine("encrypted msg="+Convert.ToBase64String(encryptedMsg));
                    byte[] fullMsg=new byte[iv.Length+desKey.Length+encryptedMsg.Length];
                    
                    iv.CopyTo(fullMsg,0);
                    desKey.CopyTo(fullMsg,iv.Length);
                    encryptedMsg.CopyTo(fullMsg,desKey.Length+iv.Length);

                    // Console.WriteLine("Full msg="+Convert.ToBase64String(fullMsg));
                    byte[] msg=Encoding.ASCII.GetBytes(Convert.ToBase64String(fullMsg));
                    client.Send(msg);

                }
                else{
                    byte[] msg=Encoding.ASCII.GetBytes(message);
                    client.Send(msg);
                    // Console.WriteLine(message);
                }

                recieveMessage(message);
            }
            catch (ArgumentNullException ane) {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            
            catch (SocketException se) {
                
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            
            catch (Exception e) {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
        }


        public void recieveMessage(string sentMsg)
        {
            sentMsg=sentMsg.ToLower();
            try{
               
                byte[] messageReceived = new byte[1024];
                int numBytes=client.Receive(messageReceived);
                string response=Encoding.ASCII.GetString(messageReceived,0,numBytes);

                if(response.Split(" ")[0]=="SHello")
                {
                    rsa.FromXmlString(response.Split(" ")[1]);
                }
                else if(sentMsg.Split(" ")[0]=="login")
                {
                        string serverRes=decryptMessageClient(response);
                        if(serverRes!="ERROR")
                        {
                            JwtSecurityTokenHandler handler=new JwtSecurityTokenHandler();
                            JwtSecurityToken token=handler.ReadJwtToken(serverRes);

                            TokenValidationParameters parameters=new TokenValidationParameters{
                                ValidateIssuer = false,
                                ValidateAudience = false,
                                ValidateLifetime = false,
                                ValidateIssuerSigningKey = true,
                                IssuerSigningKey=new RsaSecurityKey(this.rsa),
                            };

                            try{
                                handler.ValidateToken(serverRes,parameters, out var validatedSecurityToken);

                            }
                            catch{
                                Console.WriteLine("Token not valid try again");
                                return ;
                            }
                            this.user=UserModel.fetchFromXml(Convert.ToInt32(token.Payload["id"]));     
                            this.user.printUserInfo();
                        }
                        else
                            Console.WriteLine(serverRes);
                }
                else if(sentMsg.Split(" ")[0]=="quit")
                {
                    return;
                }
                else
                {
                        string serverRes=decryptMessageClient(response);
                        Console.WriteLine(serverRes);
                }
                

               
                       
            }
            catch (ArgumentNullException ane) {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            
            catch (SocketException se) {
                
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            
            catch (Exception e) {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
        }
      
       
    }
}