azure-mpi-in-a-box
==================

A CloudService that installs and configures MS-MPI along with a Cygwin OpenSSH server for remote access.

Building
----
You need the following installed in order to package up the project:
* Visual Studio 2013
* Azure SDK 2.3

Before packaging the Cloud Service in Visual Studio, you will also need to update several placeholder values in the .cscfg file that is part of the project:

```xml
<?xml version="1.0" encoding="utf-8"?>
<ServiceConfiguration serviceName="MPIClusterService" xmlns="http://schemas.microsoft.com/ServiceHosting/2008/10/ServiceConfiguration" osFamily="3" osVersion="*" schemaVersion="2014-01.2.3">
  <Role name="MPIClusterRole">
    <Instances count="2" />
    <ConfigurationSettings>
      <Setting name="adminuser" value="admin" />
      <Setting name="adminuser.publickey" value="[admin-public-key]" />
      <Setting name="jobuser" value="jobuser" />
      <Setting name="jobuser.publickey" value="[jobuser-public-key]" />
      <Setting name="blob.storageurl" value="http://rescale.blob.core.windows.net" />
    </ConfigurationSettings>
    <Certificates></Certificates>
  </Role>
</ServiceConfiguration>
```

First, make sure to specify the number of A9 instances that should be launched in the Instances element. Next, at minimum, you’ll need to provide values for the `adminuser.publickey` and `jobuser.publickey` settings so you can login to the machines after they boot. The different ConfigurationSettings are listed below:

Name | Description
---- | -----------
adminuser | The name of the user that will be created in the Administrators group
adminuser.publickey | The SSH public key for the adminuser. Added to the ~/.ssh/authorized_keys list.
jobuser | The name of the less-privileged user that will be created in the Users group. This is the user that should run mpiexec.
jobuser.publickey | The SSH public key for the jobuser. Added to the ~/.ssh/authorized_keys list.
blob.storageurl | The startup script will download programs from this location when booting up. The MS-MPI and Cygwin distributables are located here. Rescale hosts the necessary files so you shouldn’t need to modify this.


Deployment
----
After the .cscfg placeholder values have been replaced, simply build the .cspkg file with Visual Studio and use either the [management web](https://manage.windowsazure.com) or API to deploy a new Cloud Service to your subscription.

Usage
----
Once the Cloud Service is up and running, you can use SSH to connect to each of the role instances. The Cloud Service is setup to use Instance Internal Endpoints to allow clients to connect to individual role instances through the load balancer. The OpenSSH server running on port 22 on the first role instance is mapped to the external port 10106. The OpenSSH server on the second role instance is mapped to 10107, the third to 10108 and so on.

So, if you deployed a cloud service called foobar.cloudapp.net, you would use the following command to connect to the first role instance in your cluster:

```sh
ssh -i [jobuser-private-key-file] -p 10106 jobuser@foobar.cloudapp.net
```

SCP can be used to transfer files into the cluster (though note that you’ll need to use -P instead of -p to specify the custom SSH port). The following command would copy localfile.exe from your local machine to the jobuser's home directory on the first role instance:

```sh
scp -i [jobuser-private-key-file] -P 10106 localfile.exe jobuser@foobar.cloudapp.net:~/
```

The startup script will launch the SMPD process on all of the machines as the user that is specified in the jobuser setting. This means that you will need to make sure to login as this user in order to run mpiexec.

A machinefile is written out to the jobuser’s home directory which can be used in the mpiexec call. For example, after SSHing into the first role instance as the jobuser, the following command will dump the hostnames of each machine in the cluster:

```sh
$ mpiexec -machinefile machinefile hostname
RD00155DC0E6D8
RD00155DC0BEB3
```

The startup script will also configure a basic Windows SMB file share amongst all the nodes in the cluster. The jobuser can access this folder from the `~/work/shared` path. This is an easy way to distribute files amongst the nodes in the cluster.

One thing to keep in mind is that `mpiexec` is a Windows executable and does not recognize Cygwin paths. As such, if you need to pass *nix style paths as arguments, you should use the cygpath utility to convert them into Windows-style paths first. For example instead of this:

```sh
# Don't do this
mpiexec -machinefile machinefile ~/work/shared/osu_latency.exe
```

You should do this instead:
```sh
mpiexec -machinefile machinefile $(cygpath -w ~/work/shared/osu_latency.exe)
```
