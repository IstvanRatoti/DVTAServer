using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using ServerDataHandling;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Xml;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;

namespace DVTA_CTF_Server
{
    class Handler
    {
        // This function is responsible for handling login requests. It will check the database for the credentials and return a users.xml file if the creds are valid.
        // The returned users.xml file is dependant on user type. An admin will get a different users.xml file than a normal user.
        // Tested and fixed. Seems to work fine now.
        public static void HandleLogin(TcpClient client, string arguments)
        {
            string[] creds = new string[2];
            XmlDocument usersxml = new XmlDocument();
            SqlDataReader data;
            NetworkStream stream = client.GetStream();
            byte[] response;

            // TODO check the way it gets split.
            try
            {
                creds = arguments.Split(new char[] { ' ' }, 2);
                creds[1] = creds[1].Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.
                Console.WriteLine("Login attempt from {0} with hash: {1}", creds[0], Crypto.HashPassword(creds[1]));
                data = Server.dBAccess.checkLogin(creds[0], Crypto.HashPassword(creds[1])).ExecuteReader();

                if (data.HasRows)
                {
                    Console.WriteLine("Login successful.\nSending users.xml...");
                    // Have to close data before we can run new sql commands.
                    data.Read();
                    int isAdmin = (int)data["isadmin"];
                    data.Close();

                    XmlDocument allusers = Server.dBAccess.GetAllUsers();
                    XmlElement root = usersxml.CreateElement("data");
                    usersxml.AppendChild(root);
                    root.InnerXml = allusers.OuterXml;

                    XmlNode clientHash = usersxml.CreateElement("clientHash");

                    // Checks if the user is an admin. Sends a different client hash based on that.
                    if (1 == isAdmin)
                    {
                        clientHash.InnerText = "ADMINHASH";
                    }
                    else
                    {
                        clientHash.InnerText = "CLIENTHASH";
                    }
                    usersxml.DocumentElement.InsertBefore(clientHash, usersxml.DocumentElement.FirstChild);

                    // Convert the Xml Document to a String.
                    XmlTextWriter xmltxt = new XmlTextWriter(new StringWriter());
                    string responseString;
                    using (StringWriter sw = new StringWriter())
                    {
                        using (XmlTextWriter tx = new XmlTextWriter(sw))
                        {
                            usersxml.WriteTo(tx);
                            responseString = sw.ToString();
                        }
                    }
                    response = Encoding.UTF8.GetBytes(responseString);
                }
                else
                {
                    Console.WriteLine("Login failed.");
                    response = Encoding.UTF8.GetBytes("InvalidCredentials");
                }

                data.Close();
            }
            catch (Exception)
            {
                response = Encoding.UTF8.GetBytes("WrongArgCount");
            }

            stream.Write(response, 0, response.Length);
            client.Close();
        }


        // This function is responsible for registering new users.
        // Tested. Works fine, it seems.
        public static void HandleRegister(TcpClient client, string arguments)
        {
            string[] userinfo = new string[3];
            NetworkStream stream = client.GetStream();
            byte[] response;

            try
            {
                userinfo = arguments.Split(new char[] { ' ' }, 3);
                userinfo[2] = userinfo[2].Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.
                Console.WriteLine("New user registered with username {0} and email {1}.", userinfo[0], userinfo[2]);

                if (Server.dBAccess.RegisterUser(userinfo[0], userinfo[1], userinfo[2]))
                {
                    response = Encoding.UTF8.GetBytes("Success\nHere is your flag: FLAG{c3r7_p1nn1n9_15_n3v3r_7h3_4n5w3r}");
                }
                else
                {
                    response = Encoding.UTF8.GetBytes("Failed");
                }
            }
            catch (Exception)
            {
                response = Encoding.UTF8.GetBytes("Failed");
            }

            stream.Write(response, 0, response.Length);
            client.Close();
        }

        // This function serves the clients with the xml containing application data.
        // It should serve a new client the first flag also.
        // Tested. Works just about right.
        public static void HandleDownloadUserXML(TcpClient client, string arguments)
        {
            NetworkStream stream = client.GetStream();
            arguments = arguments.Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.
            Console.WriteLine("Serving data to user {0}", arguments);
            byte[] response = Encoding.UTF8.GetBytes(Server.dBAccess.GetExpenses(arguments));
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        // Receives the user's local xml after the user clicks logout. It stores the data found the in the database.
        // Tested. Works fine, but the sql part is a bit...brutish.
        public static void HandleUploadUserXML(TcpClient client, string arguments)
        {
            string[] data = new string[2];
            try
            {
                data = arguments.Split(new char[] { ' ' }, 2);
            }
            catch (Exception)
            {
                Console.WriteLine("Wrong number of arguments!");
            }
            data[1] = data[1].Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.

            NetworkStream stream = client.GetStream();
            Console.WriteLine("Receiving data from user {0}", data[0]);
            Server.dBAccess.AddExpenses(data[0], data[1]);

            client.Close();
        }

        // Undocumented method that enables login using only the password hash.
        // Basically, the same as login...it does not do the hashing.
        // Tested and fixed. Seems to work properly.
        public static void HandlePassTheHashLogin(TcpClient client, string arguments)
        {
            string[] creds = new string[2];
            XmlDocument usersxml = new XmlDocument();
            SqlDataReader data;
            NetworkStream stream = client.GetStream();
            string responseString;

            // TODO check the way it gets split.
            try
            {
                creds = arguments.Split(new char[] { ' ' }, 2);
                creds[1] = creds[1].Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.
                Console.WriteLine("Login attempt from {0} with hash: {1}", creds[0], creds[1]);
                data = Server.dBAccess.checkLogin(creds[0], creds[1]).ExecuteReader();

                if (data.HasRows)
                {
                    Console.WriteLine("Login successful.\nSending users.xml...");
                    // Have to close data before we can run new sql commands.
                    data.Read();
                    int isAdmin = (int)data["isadmin"];
                    data.Close();

                    XmlDocument allusers = Server.dBAccess.GetAllUsers();
                    XmlElement root = usersxml.CreateElement("data");
                    usersxml.AppendChild(root);
                    root.InnerXml = allusers.OuterXml;

                    XmlNode clientHash = usersxml.CreateElement("clientHash");

                    // Checks if the user is an admin. Sends a different client hash based on that.
                    if (1 == isAdmin)
                    {
                        clientHash.InnerText = "ADMINHASH";
                    }
                    else
                    {
                        clientHash.InnerText = "CLIENTHASH";
                    }
                    usersxml.DocumentElement.InsertBefore(clientHash, usersxml.DocumentElement.FirstChild);

                    // Convert the Xml Document to a String.
                    XmlTextWriter xmltxt = new XmlTextWriter(new StringWriter());
                    using (StringWriter sw = new StringWriter())
                    {
                        using (XmlTextWriter tx = new XmlTextWriter(sw))
                        {
                            usersxml.WriteTo(tx);
                            responseString = sw.ToString();
                        }
                    }
                }
                else
                {
                    data.Close();
                    Console.WriteLine("Login failed.");
                    responseString = "InvalidCredentials";
                }
            }
            catch (Exception)
            {
                responseString = "WrongArgCount";
            }

            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);
            client.Close();
        }

        // Removing this, I don't know what to use this for.
        /*public static void HandleViewProfile(TcpClient client, string arguments)
        {
            NetworkStream stream = client.GetStream();
            arguments = arguments.Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.
            Console.WriteLine("Viewing profile of user {0}", arguments);
            byte[] response = Encoding.UTF8.GetBytes(Server.dBAccess.ViewProfile(arguments));
            stream.Write(response, 0, response.Length);

            client.Close();
        }*/

        // Fixed her up a bit. Works ok now.
        public static void HandleTestDBConnection(TcpClient client, string arguments)
        {
            string[] data = new string[2];

            string responseString = String.Empty;
            string server = String.Empty;
            string database = String.Empty;

            try
            {
                data = arguments.Split(new char[] { ' ' }, 2);
                data[1] = data[1].Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.

                if ("ADMINHASH" != data[0])
                {
                    responseString = "You are not an admin!";
                }
                else
                {
                    XmlDocument doc = new XmlDocument();
                    try
                    {
                        // This looks a bit lame, but this is the easiest way I can create an XML injection.
                        doc.LoadXml("<?xml version='1.0' encoding='utf-8'?><data><server>127.0.0.1\\SQLEXPRESS</server><database>" + data[1] + "</database></data>");

                        foreach (XmlNode node in doc.DocumentElement.ChildNodes)
                        {
                            if ("server" == node.Name)
                            {
                                //Console.WriteLine(node.InnerText);
                                server = node.InnerText;
                            }
                            else if ("database" == node.Name)
                            {
                                //Console.WriteLine(node.InnerText);
                                database = node.InnerText;
                            }
                        }

                        Console.WriteLine("Testing DB connection to {0}\\{1}", server, database);

                        try
                        {
                            DBAccessClass testAccess = new DBAccessClass();
                            testAccess.OpenTestConnection(server, database);

                            responseString = "Successfully connected to the following instance: " + server + "\nDatabase used:" + database;
                            Console.WriteLine(responseString);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            responseString = e.ToString();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        responseString = e.ToString();
                    }
                }
            }
            catch (Exception)
            {
                responseString = "Wrong number of arguments!";
            }

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        // Handles a request to back up the flag to the ftp server. It expects 3 arguments: Admin hash, username and encryption/decryption key.
        // Tested and fixed. Works fine.
        public static void HandleBackupFiles(TcpClient client, string arguments)
        {
            string[] creds = new string[2];
            string responseString = string.Empty;
            //string key = "klvd";
            string key = "key";
            try
            {
                arguments = arguments.Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.

                if ("ADMINHASH" != arguments)
                {
                    responseString = "You are not an admin!";
                }
                else
                {
                    creds = Server.dBAccess.GetFTPCredentials();
                    if (creds[1] == string.Empty || creds[0] == string.Empty)
                    {
                        responseString = "Something went wrong!";
                    }
                    else
                    {
                        string password = Crypto.DecryptPassword(creds[1], key);
                        Console.WriteLine(password);

                        using (System.Net.WebClient ftpclient = new System.Net.WebClient())
                        {
                            try
                            {
                                ftpclient.Credentials = new System.Net.NetworkCredential(creds[0], password);
                                //Console.WriteLine("flag" + DateTime.Now.Hour + DateTime.Now.Minute + DateTime.Now.Second + ".txt");
                                ftpclient.UploadFile("ftp://localhost/" + "flag" + DateTime.Now.Hour + DateTime.Now.Minute + DateTime.Now.Second + DateTime.Now.Millisecond + ".txt", "STOR", "ftp_flag.txt");

                                responseString = "Success!";
                            }
                            catch (Exception ftpexc)
                            {
                                Console.WriteLine(ftpexc);
                                responseString = "Could not log in!\n The password used: " + password;
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                responseString = "Wrong number of arguments!";
            }

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        // This function Handles checking the logs. It expects 2 arguments: the admin hash and serialized data in base64 encoded format.
        // Tested and fixed. Works ok, though the default systeminfo command might take some time to run...
        public static void HandleCheckLog(TcpClient client, string arguments)
        {
            string[] data = new string[2];
            byte[] serialData;
            string responseString = string.Empty;
            try
            {
                data = arguments.Split(new char[] { ' ' }, 2);
                data[1] = data[1].Trim('\0').Trim('\n');    // Handles the excess newline and null characters at the end of the datastream.

                if ("ADMINHASH" != data[0])
                {
                    responseString = "You are not an admin!";
                }
                else
                {
                    try
                    {
                        // Cheat code to get serialized data
                        /*SystemInfo checkLog = new SystemInfo();
                        BinaryFormatter fmtExample = new BinaryFormatter();
                        MemoryStream stmExample = new MemoryStream();
                        fmtExample.Serialize(stmExample, checkLog);
                        string serialExample = Convert.ToBase64String(stmExample.ToArray());
                        Console.WriteLine(serialExample);*/

                        serialData = Convert.FromBase64String(data[1]);

                        BinaryFormatter fmt = new BinaryFormatter();
                        MemoryStream stm = new MemoryStream(serialData);
                        IRunnable run = (IRunnable)fmt.Deserialize(stm);

                        responseString = run.Run();
                    }
                    catch (Exception e)
                    {
                        responseString = e.ToString();
                    }
                }
            }
            catch (Exception)
            { 
                responseString = "Wrong number of arguments!";
            }

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        public static void HandleUnknownCommand(TcpClient client, string arguments)
        {
            string responseString = "Unknown command! The list of available commands:\n" +
                "login <username> <password>\n" +
                "regis <username> <password> <email>\n" +
                "dlxml <username>\n" +
                "ulxml <username> <xmlfile>\n" +
                "vwprf <username>\n" +
                "pthlg <username> <hash> - Depricated! Remove it, Dave!\n";

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }
    }
}
