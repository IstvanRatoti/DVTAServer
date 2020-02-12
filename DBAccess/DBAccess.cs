﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Security.Cryptography;
using System.Data.SqlClient;
using System.Data;
using System.Xml;
using System.IO;

namespace ServerDataHandling
{
    public class DBAccessClass
    {
        String decryptedDBPassword;
        SqlConnection conn;
        
        //Function to Decrypt DB Password. Is this really necessary?
        public String decryptPassword()
        {
            String dbpassword = System.Configuration.ConfigurationManager.AppSettings["DBPASSWORD"].ToString();
            String key = System.Configuration.ConfigurationManager.AppSettings["AESKEY"].ToString();
            String IV = System.Configuration.ConfigurationManager.AppSettings["IV"].ToString();
            
            byte[] encryptedBytes = Convert.FromBase64String(dbpassword);

            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Key = System.Text.ASCIIEncoding.ASCII.GetBytes(key);
            aes.IV = System.Text.ASCIIEncoding.ASCII.GetBytes(IV);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform crypto = aes.CreateDecryptor(aes.Key, aes.IV);
            byte[] decryptedbytes = crypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            decryptedDBPassword = System.Text.ASCIIEncoding.ASCII.GetString(decryptedbytes);
           
           // checking if password is successfully decrypted

            Console.WriteLine(decryptedDBPassword);

            return decryptedDBPassword;
        }

        // open connection
        public void OpenConnection()
        {
            String dbserver = System.Configuration.ConfigurationManager.AppSettings["DBSERVER"].ToString();
            String dbname = System.Configuration.ConfigurationManager.AppSettings["DBNAME"].ToString();
            String dbusername = System.Configuration.ConfigurationManager.AppSettings["DBUSERNAME"].ToString();
            
            String dbpassword = decryptPassword();
            
            Console.WriteLine("Decrypted dbpasword: "+dbpassword);

            String connectionString = "Data Source = "+dbserver+"; Initial Catalog="+dbname+"; User Id="+dbusername+"; Password="+dbpassword+";Integrated Security=false";
           
            Console.WriteLine(connectionString);

            conn = new SqlConnection();
            conn.ConnectionString = connectionString;
            conn.Open();
        }

        // open test connection
        public void OpenTestConnection(string server, string database)
        {
            String dbusername = System.Configuration.ConfigurationManager.AppSettings["DBUSERNAME"].ToString();

            String dbpassword = decryptPassword();

            Console.WriteLine("Decrypted dbpasword: " + dbpassword);

            String connectionString = "Data Source = " + server + "; Initial Catalog=" + database + "; User Id=" + dbusername + "; Password=" + dbpassword + ";Integrated Security=false";

            Console.WriteLine(connectionString);

            conn = new SqlConnection();
            conn.ConnectionString = connectionString;
            conn.Open();
        }

        // user login
        public SqlDataReader checkLogin(String clientusername,String clientpassword)
        {
            // Will need to fortify this query against sql injections.
            String sqlcmd = "SELECT * FROM users where username='" + clientusername + "' and password='" + clientpassword + "'";
            Console.WriteLine(sqlcmd);
           
           
            SqlCommand cmd = new SqlCommand(sqlcmd, conn);
           
            /*
            SqlDataAdapter sda = new SqlDataAdapter(cmd);
            DataTable dt = new DataTable();
            sda.Fill(dt);

           
            int numrowsreturned = dt.Rows.Count;
            return numrowsreturned;
            */

            SqlDataReader dtr = cmd.ExecuteReader();

            return dtr;
        }

        // User Registration
        public bool RegisterUser(String clientusername, String clientpassword, String clientemailid)
        {
            bool output = false;
            int isadmin = 0;

            // This query needs to be vulnerable to a blind sql injection. Or not? I could have just one way to admin...PTH seems like a clever idea.
            string sqlquery = "insert into users values('" + clientusername + "','" + Crypto.HashPassword(clientpassword) + "','" + clientemailid + "','" + isadmin + "')";
            SqlCommand cmd = new SqlCommand(sqlquery, conn);

            try
            {
                cmd.ExecuteNonQuery();
                output = true;
               
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }

            return output;
        }

        public void AddExpenses(string username, string xmlString)
        {
            XmlDocument xmldoc = new XmlDocument();
            xmldoc.LoadXml(xmlString);

            // Clear data already present in the sql database. Is it actually needed? Also, need to protect this against sql injection.
            string sqlquery = "delete * from expenses where username='" + username + "'";
            SqlCommand cmd = new SqlCommand(sqlquery, conn);

            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            // iterate through each item and call addExpense to put them into the database.
            foreach(XmlNode node in xmldoc.DocumentElement.ChildNodes)
            {
                if(AddExpense(node.ChildNodes[0].InnerText, node.ChildNodes[1].InnerText, node.ChildNodes[2].InnerText, node.ChildNodes[3].InnerText, node.ChildNodes[4].InnerText))
                {
                    continue;
                }
                else
                {
                    break;
                }
            }
        }

        public bool AddExpense(String adduser, String additem, String addprice, String addDate, String addTime)
        {
            bool output = false;
            string sqlquery = "insert into expenses values('" + adduser + "','" + additem + "','" + addprice + "','" + addDate + "','" + addTime + "')";
            SqlCommand cmd = new SqlCommand(sqlquery, conn);

            try
            {
                cmd.ExecuteNonQuery();
                output = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            return output;
        }

        public string GetExpenses(String username)
        {
            DataTable objData = new DataTable();
            XmlTextWriter xmlTxtWriter = new XmlTextWriter(new StringWriter());

            SqlCommand objCommand = new SqlCommand("select item, price, date, time from expenses where username='"+username+"'", conn);

            // Read the data, then do some magic to convert it to an xml string.
            SqlDataReader rdr = objCommand.ExecuteReader();
            if(rdr.HasRows)
            {
                // Return existing user data.
                objData.Load(rdr);
                objData.WriteXml(xmlTxtWriter);
                return xmlTxtWriter.ToString();
            }
            else
            {
                // Return flag if user did not exist.
                return "<data><item><name>FLAG</name><price>1</price><date>1970-01-01</date><time>15:30</time></item></data>";
            }
        }
        
        public XmlDocument GetAllUsers()
        {
            XmlDocument allusers = new XmlDocument();
            DataTable objData = new DataTable();
            XmlTextWriter xmlTxtWriter = new XmlTextWriter(new StringWriter());

            SqlCommand objCommand = new SqlCommand("select id, username, password, isadmin from users", conn);

            // Read the data, then do some magic to convert it to an xml string.
            SqlDataReader rdr = objCommand.ExecuteReader();
            objData.Load(rdr);
            objData.WriteXml(xmlTxtWriter);
            allusers.LoadXml(xmlTxtWriter.ToString());

            return allusers;
         }

        public bool ClearExpenses(String emailid)
        {
            bool output = false;
            String sqlcmd = "DELETE FROM expenses where email='" + emailid + "'";
            SqlCommand cmd = new SqlCommand(sqlcmd, conn);

            try
            {
                cmd.ExecuteNonQuery();
                output = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            return output;
        }

        public string ViewProfile(string clientusername)
        {
            string email;
            String sqlcmd = "SELECT email FROM users where username='" + clientusername + "'";
            Console.WriteLine(sqlcmd);

            SqlCommand cmd = new SqlCommand(sqlcmd, conn);

            try
            {
                SqlDataReader dtr = cmd.ExecuteReader();
                email = dtr.GetString(0);
            }
            catch(Exception e)
            {
                email = e.ToString();
            }

            return email;
        }

        public string GetFTPCredentials()
        {
            string password = String.Empty;

            String sqlcmd = "SELECT password FROM ftpcreds";
            Console.WriteLine(sqlcmd);

            SqlCommand cmd = new SqlCommand(sqlcmd, conn);

            try
            {
                SqlDataReader dtr = cmd.ExecuteReader();
                password = dtr.GetString(0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            return password;
        }

        //close connection
        public void closeConnection()
        {
            conn.Close();
        }
    }
}