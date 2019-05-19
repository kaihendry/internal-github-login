SECRETS := ./.env

up: up.json
	up

up.json: up.json.in
	test -f $(SECRETS) && . $(SECRETS); envsubst < $< > $@

clean:
	rm up.json
