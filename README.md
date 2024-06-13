## check_client_secret_exp

check azure app registration client secret expiration

### prerequisites

This script uses theses libs : 
REST::Client, Data::Dumper,  Monitoring::Plugin, File::Basename, JSON, Readonly, URI::Encode, DateTime

to install them type :

```
(sudo) cpan REST::Client Data::Dumper JSON Readonly Monitoring::Plugin File::Basename URI::Encode DateTime
```

this script writes the authentication information in the /tmp directory it will be necessary to verify that this directory exists and that the account which will launch the script has the necessary access permissions.

this scrip use an azure app registration  azure with access permissions on  graph api : type application,  Organization.Read.All et Directory.Read.All.

### Use case

```bash
check_client_secret_exp.pl 1.0.1

This nagios plugin is free software, and comes with ABSOLUTELY NO WARRANTY.
It may be used, redistributed and/or modified under the terms of the GNU
General Public Licence (see http://www.fsf.org/licensing/licenses/gpl.txt).

check_client_secret_exp.pl check azure app registration secret expiration

Usage: check_client_secret_exp.pl  [-v] -T <TENANTID> -I <CLIENTID> -p <CLIENTSECRET>  [-N <APPNAME>] [-i <RESSOURCEAPPID>] [-w <WARNING>] [-c <CRITICAL>]


 -?, --usage
   Print usage information
 -h, --help
   Print detailed help screen
 -V, --version
   Print version information
 --extra-opts=[section][@file]
   Read options from an ini file. See https://www.monitoring-plugins.org/doc/extra-opts.html
   for usage and examples.
 -T, --tenant=STRING
   The GUID of the tenant to be checked
 -I, --clientid=STRING
   The GUID of the registered application
 -p, --clientsecret=STRING
   Access Key of registered application
 -N, --appname=STRING
   name of the app registration let this empty to get all secret expiration
 -i, --resourceappid=STRING
   Ressource app Id of the app registration let this empty to get all secret expiration
 -w, --warning=threshold
   See https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT for the threshold format.
 -c, --critical=threshold
   See https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT for the threshold format.
 -t, --timeout=INTEGER
   Seconds before plugin times out (default: 30)
 -v, --verbose
   Show details for command-line debugging (can repeat up to 3 times)
```

sample : 

```bash
perl  -T <TENANTID> -I <CLIENTID> -p <CLIENTID> -N <APPNAME> -w @0:30 -c @0:30
```

you may get :

```bash
OK - APPNAME secret key time remaining 630.796 days | APPNAME_0=630.796;@0:30;@0:30
```
