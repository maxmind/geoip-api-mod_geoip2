To use from PHP, use something like:

GeoIP Country:
<%
$country_code = apache_note("GEOIP_COUNTRY_CODE");
$country_name = apache_note("GEOIP_COUNTRY_NAME");
%>

GeoIP Region:
<%
$country_code = apache_note("GEOIP_COUNTRY_CODE");
$country_name = apache_note("GEOIP_REGION");
%>

GeoIP City:
<%
$country_code = apache_note("GEOIP_COUNTRY_CODE");
$country_name = apache_note("GEOIP_CITY");
%>

==================================================
Redirection with PHP

$country_code = apache_note("GEOIP_COUNTRY_CODE");
  if ( $country_code == "DE" )
  {
  header ("Location: http://www.google.de" );
  }  
  else
  {
  header ("Location: http://www.yoursite.com" );
  }
