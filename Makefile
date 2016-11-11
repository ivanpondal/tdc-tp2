.PHONY: all clean

GEOLITE_DB = GeoLite2-City.mmdb
GEOLITE_DB_GZ = $(addsuffix .gz, $(GEOLITE_DB))

all: geoip2

clean:
	rm -rf $(GEOLITE_DB)

$(GEOLITE_DB_GZ):
	wget "http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz"

$(GEOLITE_DB): $(GEOLITE_DB_GZ)
	gunzip GeoLite2-City.mmdb.gz

geoip2: $(GEOLITE_DB)
	pip install --user geoip2
