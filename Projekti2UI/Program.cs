using System;

namespace Projekti2UI
{
    class Program
    {
        static void Main(string[] args)
        {
           
            int choice=Convert.ToInt32(Console.ReadLine());
            if(choice ==0)
            {

                 Server server=new Server();
                server.listen();                 
            }
            else{
                Client c =new Client();
            }
    }
}
}
