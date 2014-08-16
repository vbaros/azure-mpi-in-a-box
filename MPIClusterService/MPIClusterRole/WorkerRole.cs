using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.IO;
using System.Text;
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.Diagnostics;
using Microsoft.WindowsAzure.ServiceRuntime;
using Microsoft.WindowsAzure.Storage;

namespace Rescale.MPIClusterRole
{
    public class WorkerRole : RoleEntryPoint
    {
        public override void Run()
        {
            // This is a sample worker implementation. Replace with your logic.
            Trace.TraceInformation("MPIClusterRole entry point called", "Information");

            while (true)
            {
                Thread.Sleep(10000);
                Trace.TraceInformation("Working", "Information");
            }
        }

        public override bool OnStart()
        {
            // Set the maximum number of concurrent connections 
            ServicePointManager.DefaultConnectionLimit = 12;

            // For information on handling configuration changes
            // see the MSDN topic at http://go.microsoft.com/fwlink/?LinkId=166357.
            var role = RoleEnvironment.Roles["MPIClusterRole"];
            StringBuilder machinefile = new StringBuilder();
            string SlsPath = RoleEnvironment.GetLocalResource("LocalStorage").RootPath;
            string jobuser = RoleEnvironment.GetConfigurationSettingValue("jobuser");
            string masterIp = null;
            // We are assuming that we have a homogenous set of RoleInstances within this cloud service so each
            // instance will contain the same number of cores.
            int cores = Environment.ProcessorCount;
            foreach (RoleInstance i in role.Instances)
            {
                if (i.Id.Split('_').Last() == "0")
                {
                    masterIp = i.InstanceEndpoints["MPI"].IPEndpoint.Address.ToString();
                    ShareFolder("C:\\shared", "SHARED");
                }
                machinefile.AppendLine(String.Format("{0} {1}", i.InstanceEndpoints["MPI"].IPEndpoint.Address, cores));
            }
            System.IO.File.WriteAllText(SlsPath + "\\cygwin64\\home\\" + jobuser + "\\machinefile", machinefile.ToString(), System.Text.Encoding.ASCII);
            using (StreamWriter sw = System.IO.File.AppendText(SlsPath + "\\cygwin64\\etc\\fstab"))
            {
                sw.WriteLine("//{0}/SHARED /home/{1}/work/shared ntfs binary,posix=0 0 0", masterIp, jobuser);
            }
            return base.OnStart();
        }

        public static void ShareFolder(string path, string shareName)
        {
            Directory.CreateDirectory(path);

            int exitCode;
            string error;

            //Grant the folder full control to everyone
            exitCode = ExecuteCommand("icacls.exe", path + " /Grant Everyone:F /Inheritance:e /T", out error, 10000);
            if (exitCode != 0)
            {
                //Log error and continue since the drive may already be shared
                Trace.WriteLine("Error granting shared path full control, error msg:" + error, "Warning");
            }

            // Explicitly Grant the folder full control to users group
            exitCode = ExecuteCommand("icacls.exe", path + " /Grant Users:(OI)(CI)F /Inheritance:e /T", out error, 10000);
            if (exitCode != 0)
            {
                //Log error and continue since the drive may already be shared
                Trace.WriteLine("Error granting shared path full control to users group, error msg:" + error, "Warning");
            }
            
            //Share the folder
            exitCode = ExecuteCommand("net.exe", " share " + shareName + "=" + path + " /Grant:Everyone,full", out error, 10000);
            if (exitCode != 0)
            {
                //Log error and continue since the drive may already be shared
                Trace.WriteLine("Error creating fileshare, error msg:" + error, "Warning");
            }
        }

        public static int ExecuteCommand(string exe, string arguments, out string error, int timeout)
        {
            Process p = new Process();
            int exitCode;
            p.StartInfo.FileName = exe;
            p.StartInfo.Arguments = arguments;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardError = true;
            p.Start();
            error = p.StandardError.ReadToEnd();
            p.WaitForExit(timeout);
            exitCode = p.ExitCode;
            p.Close();

            return exitCode;
        }
    }
}
