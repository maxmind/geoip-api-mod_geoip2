Please Note:
apache_note is not supported in Apache2 with PHP versions < 4.3

Instead use something like

$country_code = $_SERVER['GEOIP_COUNTRY_CODE'];
$country_name = $_SERVER['GEOIP_COUNTRY_NAME'];

To use from PHP, use something like:

<%
$country_code = apache_note("GEOIP_COUNTRY_CODE");
$country_name = apache_note("GEOIP_COUNTRY_NAME");
%>
