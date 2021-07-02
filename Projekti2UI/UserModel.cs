using System;
using System.Security.Cryptography;
using System.Xml;
using System.Text;


namespace Projekti2UI{
    
    public class UserModel{
        private int id;
        private string username;
        private string password;
        private string salt;

       public UserModel(int id,string username,string pwd,string salt)
       {
           this.id=id;
           this.username=username;
           this.password=pwd;
           this.salt=salt;
       }

       public UserModel(string username,string pwd)
       {
           this.id=getNewId();
           this.username=username;
           this.salt=generateSalt();
           this.password=hashPassword(pwd);
       }

       public static UserModel fetchFromXml(int id)
       {
           XmlDocument doc=new XmlDocument();
           doc.Load("../data/users.xml");
           XmlNodeList users=doc.GetElementsByTagName("user");

           for (int i = 0; i < users.Count; i++)
           {
               XmlNode user =users.Item(i);
               
               if(user["id"].InnerText==Convert.ToString(id))
               {
                    return new UserModel(Convert.ToInt32(user["id"].InnerText),user["username"].InnerText,user["password"].InnerText,user["salt"].InnerText);

               }

           }
           return null;
       }


       public void printUserInfo()
       {
           Console.WriteLine("------------User Info------------");
           Console.WriteLine("Username="+this.usernameGetSet);
           Console.WriteLine("Id="+this.idGetSet);
           Console.WriteLine("---------------------------------");


       }

       public int idGetSet{
           get{
               return this.id;
           }
           set{
               this.id=value;
           }

       }    


       public void addExpense(string name,string type,string value,string year,string month)
       {
            XmlDocument doc=new XmlDocument();
            doc.Load("../data/expenses.xml");
            XmlElement root=doc.DocumentElement;
            XmlElement expense=doc.CreateElement("expense");
            
            XmlElement expenseName=doc.CreateElement("name");
            expenseName.InnerText=Convert.ToString(name);
            expense.AppendChild(expenseName);

            XmlElement expenseValue=doc.CreateElement("value");
            expenseValue.InnerText=value;
            expense.AppendChild(expenseValue);

            XmlElement expenseType=doc.CreateElement("type");
            expenseType.InnerText=type;
            expense.AppendChild(expenseType);

            XmlElement expenseYear=doc.CreateElement("year");
            expenseYear.InnerText=year;
            expense.AppendChild(expenseYear);
            
            XmlElement expenseMonth=doc.CreateElement("month");
            expenseMonth.InnerText=month;
            expense.AppendChild(expenseMonth);

            XmlElement expenseUser=doc.CreateElement("userId");
            expenseUser.InnerText=this.idGetSet.ToString();
            expense.AppendChild(expenseUser);

            root.AppendChild(expense);

            doc.Save("../data/expenses.xml");

       }


        public void listExpenses()
        {
            XmlDocument doc=new XmlDocument();
            doc.Load("../data/expenses.xml");

            int expNum=0;

            XmlNodeList expenses=doc.GetElementsByTagName("expense");
            for (int i = 0; i < expenses.Count; i++)
            {
                XmlNode exp=expenses.Item(i);
                if(exp["userId"].InnerText==this.idGetSet.ToString())
                {
                    Console.WriteLine("----------------------");
                    Console.WriteLine("Name="+exp["name"].InnerText);
                    Console.WriteLine("value="+exp["value"].InnerText);
                    Console.WriteLine("type="+exp["type"].InnerText);
                    Console.WriteLine("year="+exp["year"].InnerText);
                    Console.WriteLine("month="+exp["month"].InnerText);
                    Console.WriteLine("----------------------");
                    expNum++;

                }
               
            }
            Console.WriteLine("This is your expense summary you have "+expNum+" expenses");
            Console.WriteLine("----------------------");

        }
       

       public string usernameGetSet{
           get{
               return this.username;
           }
           set{
               this.username=value;
           }
       }

       public string pass{
           get{
               return this.password;
           }
           set{
               this.password=hashPassword(value);
           }
       }

        public string saltGetSet{
            get{
                return this.salt;
            }
            set{
                this.salt=generateSalt();
            }
        }

        


        public string hashPassword(string pwd)
        {
            MD5 md5 =MD5.Create();

            byte[] input=Encoding.ASCII.GetBytes(pwd+salt);
 
            byte[] bytes=md5.ComputeHash(input);

           
            return Convert.ToBase64String(bytes);

        }
        public string generateSalt()
        {   
            byte[] bytes=new byte[12];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetNonZeroBytes(bytes);
            
            
            return Convert.ToBase64String(bytes);
        }
        
        public int getNewId()
        {
            XmlDocument doc =new XmlDocument();
            doc.Load("../data/users.xml");
            if(doc.GetElementsByTagName("user").Count == 0)
            {
                return 1;
            }
            else{
                XmlNode users=doc.GetElementsByTagName("users")[0];
                Console.WriteLine(users.LastChild["id"].InnerText);
            
                return  Convert.ToInt32(users.LastChild["id"].InnerText)+1;
            }
           
        }
    }
}