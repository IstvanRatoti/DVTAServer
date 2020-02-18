using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DVTA_CTF_Server
{
    interface IRunnable
    {
        string Run();
    }

    [Serializable]
    class CheckLog : IRunnable
    {
        public string Run()
        {
            return "Not implemented yet! Dave is working on this, along with another awesome feature!";
        }
    }

    [Serializable]
    class SystemInfo : IRunnable
    {
        private string cmd = "systeminfo";

        public string Run()
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + this.cmd;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            Console.WriteLine("Running command " + this.cmd);
            process.Start();
            // Read the output (or the error)
            string output = process.StandardOutput.ReadToEnd();
            //Console.WriteLine(output);
            string error = process.StandardError.ReadToEnd();
            //Console.WriteLine(error);
            process.WaitForExit();

            return "WIP! Talk to Dave about this awesome idea.\nCommand " + this.cmd + "ran successfully! Output:\n" + output + error;
        }
    }
}
