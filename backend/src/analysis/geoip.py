import geoip2.database
import os
import ipaddress

class GeoIPLookup:
    def __init__(self, city_db_name="GeoLite2-City.mmdb", country_db_name="GeoLite2-Country.mmdb", asn_db_name="GeoLite2-ASN.mmdb"):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_folder = os.path.join(script_dir, "geolite_databases")

        city_db_path = os.path.join(db_folder, city_db_name)
        country_db_path = os.path.join(db_folder, country_db_name)
        asn_db_path = os.path.join(db_folder, asn_db_name)

        self.city_reader = None
        self.country_reader = None
        self.asn_reader = None
        self.is_ready = False

        try:
            if os.path.exists(city_db_path):
                self.city_reader = geoip2.database.Reader(city_db_path)
                print(f"GeoIP City DB loaded from: {city_db_path}")
                self.is_ready = True
            else:
                print(f"Warning: GeoIP City DB not found at {city_db_path}")
        except Exception as e:
            print(f"Error loading GeoIP City DB: {e}")
        
        try:
            if os.path.exists(country_db_path) and not self.city_reader: # Only load if city isn't already providing country
                self.country_reader = geoip2.database.Reader(country_db_path)
                print(f"GeoIP Country DB loaded from: {country_db_path}")
                self.is_ready = True 
            elif self.city_reader:
                pass # City DB already provides country info
            else:
                 print(f"GeoIP Country DB not found at {country_db_path}")
        except Exception as e:
            print(f"Error loading GeoIP Country DB: {e}")

        try:
            if os.path.exists(asn_db_path):
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                print(f"GeoIP ASN DB loaded from: {asn_db_path}")
                self.is_ready = True
            else:
                print(f"Warning: GeoIP ASN DB not found at {asn_db_path}")
        except Exception as e:
            print(f"Error loading GeoIP ASN DB: {e}")

        if not self.is_ready:
            print("CRITICAL WARNING: No GeoIP databases loaded. GeoIP lookups will fail or return None.")
        
    def _is_resolvable_ip(self, ip_address_str: str) -> bool:
       
        try:
            ip_obj = ipaddress.ip_address(ip_address_str)
            return ip_obj.is_global and not ip_obj.is_multicast and \
                   not ip_obj.is_loopback and not ip_obj.is_link_local and \
                   not ip_obj.is_reserved
        except ValueError:
            return False 
    def get_location_info(self, ip_address: str):
        if not self.is_ready or not self._is_resolvable_ip(ip_address):
            return None
        
        try:
            if self.city_reader:
                response = self.city_reader.city(ip_address)
                return {
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "country": response.country.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude
                }
            elif self.country_reader:
                response = self.country_reader.country(ip_address)
                return {
                    "country_code": response.country.iso_code,
                    "country": response.country.name
                }
        except Exception as e:
            print(f"Error during GeoIP lookup for {ip_address}: {e}")
        
        return None
    
    def get_asn_info(self, ip_address: str):
        if not self.is_ready or not self._is_resolvable_ip(ip_address):
            return None
        
        try:
            if self.asn_reader:
                response = self.asn_reader.asn(ip_address)
                return {
                    "asn": response.autonomous_system_number,
                    "organization": response.autonomous_system_organization
                }
        except Exception as e:
            print(f"Error during GeoIP ASN lookup for {ip_address}: {e}")
        
        return None

    def get_combined_info(self, ip_address: str) -> dict:
        
        info = {"ip": ip_address}
        location = self.get_location_info(ip_address)
        asn = self.get_asn_info(ip_address)
        if location:
            info.update(location)
        if asn:
            info.update(asn)
        return info

    def close(self):

        if self.city_reader:
            self.city_reader.close()
        if self.country_reader:
            self.country_reader.close()
        if self.asn_reader:
            self.asn_reader.close()
        print("GeoIP readers closed.")

# if __name__ == "__main__":
#     geoip = GeoIPLookup()
#     test_ip = "8.8.8.8"
#     print(f"Testing GeoIP lookup for {test_ip}...")
#     location_info = geoip.get_combined_info(test_ip)
#     if location_info:
#         print(f"Location info for {test_ip}: {location_info}")
#     else:
#         print(f"No location info found for {test_ip}.")

