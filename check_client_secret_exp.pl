#!/usr/bin/perl -w
#===============================================================================
# Script Name   : check_client_secret_exp.pl
# Usage Syntax  : check_client_secret_exp.pl [-v] -T <TENANTID> -I <CLIENTID> -p <CLIENTSECRET>   [-N <APPNAME>] [-i <RESSOURCEAPPID>] [-w <WARNING>] [-c <CRITICAL>] 
# Author        : DESMAREST JULIEN (Start81)
# Version       : 1.0.1
# Last Modified : 13/06/2024 
# Modified By   : DESMAREST JULIEN (Start81)
# Description   : check app registration secret key expiration
# Depends On    : REST::Client, Data::Dumper,  Monitoring::Plugin, File::Basename, JSON, Readonly, URI::Encode, DATETIME 
#
# Changelog:
#    Legend:
#       [*] Informational, [!] Bugix, [+] Added, [-] Removed
# - 03/06/2024 | 1.0.0 | [*] initial realease
# - 13/06/2024 | 1.0.1 | [*] Improve return when APPNAME not found or RESSOURCEAPPID not found
# 
#===============================================================================
use REST::Client;
use Data::Dumper;
use JSON;
use utf8;
use File::Basename;
use DateTime;
use strict;
use warnings;
use Readonly;
use Monitoring::Plugin;
use URI::Encode;
Readonly our $VERSION => '1.0.1';
my $graph_endpoint = "https://graph.microsoft.com";
my @apps_name = ();
my @criticals = ();
my @warnings = ();
my @ok = ();
my $result;
my $o_verb;
sub verb { my $t=shift; print $t,"\n" if ($o_verb) ; return 0}
my $me = basename($0);
my %ssl=('NO'=>0,'SSL'=> 'ssl' ,'TLS'=>'starttls');
my $client = REST::Client->new();
my $np = Monitoring::Plugin->new(
    usage => "Usage: %s  [-v] -T <TENANTID> -I <CLIENTID> -p <CLIENTSECRET>  [-N <APPNAME>] [-i <RESSOURCEAPPID>] [-w <WARNING>] [-c <CRITICAL>]   \n ",
    plugin => $me,
    shortname => " ",
    blurb => "$me check azure app registration secret expiration",
    version => $VERSION,
    timeout => 30
);

#write content in a file
sub write_file {
    my ($content,$tmp_file_name) = @_;
    my $fd;
    verb("write $tmp_file_name");
    if (open($fd, '>', $tmp_file_name)) {
        print $fd $content;
        close($fd);       
    } else {
        my $msg ="unable to write file $tmp_file_name";
        $np->plugin_exit('UNKNOWN',$msg);
    }
    
    return 0
}

#Read previous token  
sub read_token_file {
    my ($tmp_file_name) = @_;
    my $fd;
    my $token ="";
    my $last_mod_time;
    verb("read $tmp_file_name");
    if (open($fd, '<', $tmp_file_name)) {
        while (my $row = <$fd>) {
            chomp $row;
            $token=$token . $row;
        }
        $last_mod_time = (stat($fd))[9];
        close($fd);
    } else {
        my $msg ="unable to read $tmp_file_name";
        $np->plugin_exit('UNKNOWN',$msg);
    }
    return ($token,$last_mod_time)
    
}

#get a new acces token
sub get_access_token{
    my ($clientid,$clientsecret,$tenantid) = @_;
    verb(" tenantid = " . $tenantid);
    verb(" clientid = " . $clientid);
    verb(" clientsecret = " . $clientsecret);
    my $uri = URI::Encode->new({encode_reserved => 1});
    my $encoded_graph_endpoint = $uri->encode($graph_endpoint . '/.default');
    verb("$encoded_graph_endpoint");
    my $payload = 'grant_type=client_credentials&client_id=' . $clientid . '&client_secret=' . $clientsecret . '&scope='.$encoded_graph_endpoint;
    my $url = "https://login.microsoftonline.com/" . $tenantid . "/oauth2/v2.0/token";
    $client->POST($url,$payload);
    if ($client->responseCode() ne '200') {
        my $msg = "response code : " . $client->responseCode() . " Message : Error when getting token" . $client->{_res}->decoded_content;
        $np->plugin_exit('UNKNOWN',$msg);
    }
    return $client->{_res}->decoded_content;
};

$np->add_arg(
    spec => 'tenant|T=s',
    help => "-T, --tenant=STRING\n"
          . '   The GUID of the tenant to be checked',
    required => 1
);
$np->add_arg(
    spec => 'clientid|I=s',
    help => "-I, --clientid=STRING\n"
          . '   The GUID of the registered application',
    required => 1
);
$np->add_arg(
    spec => 'clientsecret|p=s',
    help => "-p, --clientsecret=STRING\n"
          . '   Access Key of registered application',
    required => 1
);
$np->add_arg(
    spec => 'appname|N=s', 
    help => "-N, --appname=STRING\n"  
         . '   name of the app registration let this empty to get all secret expiration',
    required => 0
);
$np->add_arg(
    spec => 'resourceappid|i=s', 
    help => "-i, --resourceappid=STRING\n"  
         . '   Ressource app Id used by the app registration let this empty to get all secret expiration',
    required => 0
);
$np->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=threshold\n" 
          . '   See https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT for the threshold format.',
    required => 0
);
$np->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=threshold\n"  
          . '   See https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT for the threshold format.',
    required => 0
);
$np->getopts;
my $msg = "";
my $tenantid = $np->opts->tenant;
my $clientid = $np->opts->clientid;
my $clientsecret = $np->opts->clientsecret; 
my $o_app_name = $np->opts->appname;
my $o_warning = $np->opts->warning;
my $o_critical = $np->opts->critical;
my $status;
my $o_resourceappid = $np->opts->resourceappid;
my $budget_founded = 0;
$o_verb = $np->opts->verbose if (defined $np->opts->verbose);
my $i = 0;
my $y = 0;
my $k = 0;
verb(" tenantid = " . $tenantid);
verb(" clientid = " . $clientid);
verb(" clientsecret = " . $clientsecret);
#Get token
my $tmp_file = "/tmp/$clientid.tmp";
my $token;
my $last_mod_time;
my $token_json;
if (-e $tmp_file) {
    
    #Read previous token
    ($token,$last_mod_time) = read_token_file ($tmp_file);
    $token_json = from_json($token);
    #check token expiration
    my $expiration =  $last_mod_time + ($token_json->{'expires_in'} - 60);
    my $current_time = time();
    verb "current_time : $current_time   exptime : $expiration\n";
    if ($current_time > $expiration ) {
        #get a new token
        $token = get_access_token($clientid,$clientsecret,$tenantid);
        write_file($token,$tmp_file);
        $token_json = from_json($token);
    }
} else {
    $token = get_access_token($clientid,$clientsecret,$tenantid);
    write_file($token,$tmp_file);
    $token_json = from_json($token);
}
verb(Dumper($token_json ));
$token = $token_json->{'access_token'};
$client->addHeader('Authorization', 'Bearer ' . $token);
$client->addHeader('Content-Type', 'application/x-www-form-urlencoded');
$client->addHeader('Accept', 'application/json');
my $url = $graph_endpoint . "/v1.0/applications";
verb($url);
$client->GET($url);
if($client->responseCode() ne '200'){
    $msg ="response code : " . $client->responseCode() . " Message : Error when getting apps list " .  $client->responseContent();
    $np->plugin_exit('UNKNOWN',$msg);
}
my $apps_list = from_json($client->responseContent());
#verb(Dumper($apps_list));


my $resourceappid_founded = 0;
my $app_founded = 0;
do {
    $resourceappid_founded = 0;
    
    if (!$o_resourceappid){
        $resourceappid_founded=1;
    }else{
        #resourceAppId
        $k=0;
        if (exists  $apps_list->{'value'}->[$i]->{'requiredResourceAccess'}->[0]){
            do{
                if (($apps_list->{'value'}->[$i]->{'requiredResourceAccess'}->[$k]->{'resourceAppId'}) eq ($o_resourceappid)) {
                    $resourceappid_founded=1;
                }
                $k++; 
            } while ((exists $apps_list->{'value'}->[$i]->{'requiredResourceAccess'}->[$k]) and (!$resourceappid_founded));
        };

    } ;    
    my $app_name = $apps_list->{'value'}->[$i]->{'displayName'};
    verb("app_name  $app_name");
    $y = 0;
    if (((!$o_app_name) or ($app_name eq  $o_app_name)) and ($resourceappid_founded)){
        $app_founded = 1;
        if (exists $apps_list->{'value'}->[$i]->{'passwordCredentials'}->[0]){
            do{
                my $end_date = $apps_list->{'value'}->[$i]->{'passwordCredentials'}->[$y]->{'endDateTime'};
                verb('endDateTime ' . $end_date);
                my $dt_now = DateTime->now;
                $dt_now->set_time_zone('UTC');
                my @temp = split('T', $end_date);
                $end_date = $temp[0];
                my $end_date_time = $temp[1];
                @temp = split('-', $end_date);
                my @temp_time = split(':', $end_date_time);
                my $dt = DateTime->new(
                    year       => $temp[0],
                    month      => $temp[1],
                    day        => $temp[2],
                    hour       => $temp_time[0],
                    minute     => $temp_time[1],
                    second     => 0,
                    time_zone  => 'UTC',
                );
                $result =  $dt->subtract_datetime_absolute($dt_now);
                my $temp;
                
                if ($result->is_negative){
                    $temp = ($result->seconds)/86400;
                    $temp = $temp*-1;

                } else {
                    $temp = ($result->seconds)/86400;
                }
                verb($temp);
                verb(Dumper ($result));
                verb("secret remaning  : " . $result);
                my $label = "$app_name"."_"."$y"; 
                $label =~ s/\s//g;
                $temp = sprintf("%.3f",$temp);
                $msg = "$app_name secret key time remaining $temp days" ;
                $np->add_perfdata(label => $label, value => $temp, warning => $o_warning, critical => $o_critical);
                if (defined($o_warning) && defined($o_critical)) {
                    $np->set_thresholds(warning => $o_warning, critical => $o_critical);
                    $status = $np->check_threshold($temp);
                    push( @criticals, "$app_name secret key expiration out of range $temp days" ) if ($status==2);
                    push( @warnings, "$app_name secret key expiration out of range $temp days") if ($status==1);
                    push (@ok,$msg) if ($status==0); 
                } else {
                    push (@ok,$msg);
                }
                $y++;
            } while (exists $apps_list->{'value'}->[$i]->{'passwordCredentials'}->[$y]);
        }
        

    } else {
        push(@apps_name,$app_name);
    }
    $i++;
} while ($apps_list->{'value'}->[$i]);
if ($o_app_name){
    if ($app_founded == 0){
        $msg = "App  " . $o_app_name . " not found  available app registration : " . join(", ", @apps_name);
        $np->plugin_exit('UNKNOWN',$msg);
    }
}
if ($o_resourceappid){
    if ($resourceappid_founded==0){
        $msg = "RessourceAppId  " . $o_resourceappid . " not found";
        $np->plugin_exit('UNKNOWN',$msg);
    }

}
$np->plugin_exit('CRITICAL', join(', ', @criticals)) if (scalar @criticals > 0);
$np->plugin_exit('WARNING', join(', ', @warnings)) if (scalar @warnings > 0);
$np->plugin_exit('OK', join(', ', @ok));
