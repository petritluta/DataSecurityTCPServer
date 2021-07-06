using System;
using System.Net;
using System.Net.Sockets;
using System.Xml;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.IO;
using System.Threading;

namespace Projekti2UI{

    class Server{
        private Socket server;
        private RSACryptoServiceProvider rsa;

        private DESCryptoServiceProvider  des;
        
        public Server()
        {         
            try{
                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddr = ipHost.AddressList[0];
                IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 11111);
                server=new Socket(ipAddr.AddressFamily,SocketType.Stream,ProtocolType.Tcp);
                server.Bind(localEndPoint);

                rsa=new RSACryptoServiceProvider();

            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
            }
           
        }


        public bool userExists(string username)
        {
            XmlDocument doc=new XmlDocument();
            doc.Load("../data/users.xml");
            XmlNodeList users=doc.DocumentElement.GetElementsByTagName("user");
            for (int i = 0; i < users.Count; i++)
            {
                XmlNode user=users.Item(i);
                if(user["username"].InnerText==username)
                    return true;
            }
            return false;
        }

        public string authenticate(string username,string pwd)
        {
             XmlDocument doc=new XmlDocument();
            doc.Load("../data/users.xml");
            XmlNodeList users=doc.DocumentElement.GetElementsByTagName("user");
            for (int i = 0; i < users.Count; i++)
            {
                XmlNode user=users.Item(i);
                if(user["username"].InnerText==username)
                {
                    MD5 md5 =MD5.Create();
                    if(user["password"].InnerText == Convert.ToBase64String(md5.ComputeHash(Encoding.ASCII.GetBytes(pwd+user["salt"].InnerText))))
                        return user["id"].InnerText;
                    else
                        return null;                    
                }
            }
            return null;
        }

        public void registerUser(string username,string pwd)
        {
            UserModel user=new UserModel(username,pwd);
        
            XmlDocument doc =new XmlDocument();
            doc.Load("../data/users.xml");
            XmlElement root=doc.DocumentElement;
            XmlElement newUser=doc.CreateElement("user");
            
            XmlElement id=doc.CreateElement("id");
            id.InnerText=Convert.ToString(user.idGetSet);
            newUser.AppendChild(id);

            XmlElement usr=doc.CreateElement("username");
            usr.InnerText=user.usernameGetSet;
            newUser.AppendChild(usr);

            XmlElement password=doc.CreateElement("password");
            password.InnerText=user.pass;
            newUser.AppendChild(password);

            XmlElement salt=doc.CreateElement("salt");
            salt.InnerText=user.saltGetSet;
            newUser.AppendChild(salt);
            
            root.AppendChild(newUser);
            doc.Save("../data/users.xml");
            
        }


        public string generateToken(int userId)
        {

            SigningCredentials credentials=new SigningCredentials(new RsaSecurityKey(rsa),SecurityAlgorithms.RsaSha256);

            JwtHeader header=new JwtHeader(credentials);
            JwtPayload payload=new JwtPayload{
                {
                    "id",userId
                }
            };

            JwtSecurityToken token=new JwtSecurityToken(header,payload);
            JwtSecurityTokenHandler handler=new JwtSecurityTokenHandler();


            return handler.WriteToken(token);
        }


        public string decryptMessage(string message)
        {
                        byte[] fullMsgData=Convert.FromBase64String(message);
                        byte[] iv=new byte[8];
                        Array.Copy(fullMsgData,iv,8);

                        byte[] enDesKey=new byte[128];
                        byte[] desKey=new byte[8];
                        Array.Copy(fullMsgData,iv.Length,enDesKey,0,128);
                        desKey=rsa.Decrypt(enDesKey,false);
                        // Console.WriteLine("iv length="+iv.Length+" iv value="+Convert.ToBase64String(iv)+" deskey  length="+enDesKey.Length+"  des encrytpted="+Convert.ToBase64String(enDesKey)+" des decrypted="+Convert.ToBase64String(desKey));

                        des=new DESCryptoServiceProvider();
                        des.IV=iv;
                        des.Key=desKey;
                        des.Mode=CipherMode.CBC;
                        
                        byte[] encryptedMessage=new byte[fullMsgData.Length-iv.Length-enDesKey.Length];
                        
                        // Console.WriteLine("Full msg="+Convert.ToBase64String(fullMsgData));
                        
                        Array.Copy(fullMsgData,iv.Length+enDesKey.Length,encryptedMessage,0,fullMsgData.Length-iv.Length-enDesKey.Length);

                        // Console.WriteLine("Encrypted message="+Convert.ToBase64String(encryptedMessage));
                        
                        MemoryStream memoryStream=new MemoryStream();
                        CryptoStream cryptoStream=new CryptoStream(memoryStream,des.CreateDecryptor(),CryptoStreamMode.Write);
                        cryptoStream.Write(encryptedMessage,0,encryptedMessage.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] decryptedMsg=memoryStream.ToArray();

                        string decryptedData=Encoding.ASCII.GetString(decryptedMsg);

                        return decryptedData;
        }


        public string encryptMessage(string message)
        {
            des.GenerateIV();    
            byte[] ivPrim=des.IV;
            des.Mode=CipherMode.CBC;
            MemoryStream memoryStream=new MemoryStream();
            CryptoStream cryptoStream=new CryptoStream(memoryStream,des.CreateEncryptor(),CryptoStreamMode.Write);
            cryptoStream.Write(Encoding.ASCII.GetBytes(message),0,Encoding.ASCII.GetBytes(message).Length);
            cryptoStream.FlushFinalBlock();
            byte[] encryptedMsg=memoryStream.ToArray();

            byte[] fullMsg=new byte[ivPrim.Length+encryptedMsg.Length];

            ivPrim.CopyTo(fullMsg,0);
            encryptedMsg.CopyTo(fullMsg,ivPrim.Length);

            return Convert.ToBase64String(fullMsg);
        }
        

        public void responseToClient(Socket client)
        {
            while(true)
            {
                    byte[] bytes=new Byte[1024];
                    string data=null;
                    int numBytes=client.Receive(bytes);
                    data+=Encoding.ASCII.GetString(bytes,0,numBytes);

              
                    if(data.ToLower() == "chello")
                    {
                        byte[] response=Encoding.ASCII.GetBytes("SHello "+rsa.ToXmlString(false));
                        client.Send(response);
                        // Console.WriteLine(rsa.ToXmlString(false));
                    }
                    else{
                        
                        
                        string decryptedData=decryptMessage(data);
                        // Console.WriteLine(decryptedData);
    
                        string command=decryptedData.Split(" ")[0].ToLower();         
                    
                        if(command=="register")
                        {
                            if(userExists(decryptedData.Split(" ")[1]))
                            {
                                byte[] response=Encoding.ASCII.GetBytes(encryptMessage("ERROR"));
                                client.Send(response);
                            }
                            else{
                                registerUser(decryptedData.Split(" ")[1],decryptedData.Split(" ")[2]);
                                byte[] response=Encoding.ASCII.GetBytes(encryptMessage("OK"));
                                client.Send(response);
                            }
                        }
                        else if(command=="login")
                        {
                            string userId=authenticate(decryptedData.Split(" ")[1],decryptedData.Split(" ")[2]);
                            if(userId != null)
                            {
                                byte[] response=Encoding.ASCII.GetBytes(encryptMessage(generateToken(Convert.ToInt32(userId))));
                                client.Send(response);
                            }
                            else{
                                byte[] response=Encoding.ASCII.GetBytes(encryptMessage("ERROR"));
                                client.Send(response);
                            }
                        }
                        else if(command =="expense")
                        {
                            UserModel usr=UserModel.fetchFromXml(Convert.ToInt32(decryptedData.Split(" ")[6]));
                            usr.addExpense(decryptedData.Split(" ")[1],decryptedData.Split(" ")[2],decryptedData.Split(" ")[3],decryptedData.Split(" ")[4],decryptedData.Split(" ")[5]);
                            byte[] response=Encoding.ASCII.GetBytes(encryptMessage("OK"));
                            client.Send(response);
                        }
                        else if(command=="quit")
                        {
                            Console.WriteLine("Byee");
                            break;
                        }

                    }
            }
            client.Shutdown(SocketShutdown.Both);
            client.Close();  
        }

        public void listen()
        {
            server.Listen(10);

            while(true)
            {

            
                Socket client=server.Accept();
                Thread thread=new Thread(()=>this.responseToClient(client));
                thread.Start();
              
               
            }
        }

       
    }
}