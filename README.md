Example from https://github.com/dghubble/gologin/tree/master/examples/google
modifications.

When deploying in production I assume you have UP_STAGE set. I assume it is
unset locally to toggle secure cookie features, since again I assume up develop
locally with [gin](https://github.com/codegangsta/gin) on **localhost:3000**.

# .env

	export GOOGLE_CLIENT_ID=427670901447-op7f2lhfd1o6qbvri9oiisr28ltv70tl.apps.googleusercontent.com
	export GOOGLE_CLIENT_SECRET=[REDACTED]
	export SESSION_SECRET=[REDACTED]

# Logging

Unauthenticated example:

	May 7th 04:55:09pm INFO staging 73c6409 request: id=d17c74c4-70a5-11e9-b4ac-79484ad3afab ip=210.23.25.246 method=GET path=/
	May 7th 04:55:09pm INFO staging 73c6409 index: auth=map[] id=d17c74c4-70a5-11e9-b4ac-79484ad3afab
	May 7th 04:55:09pm INFO staging 73c6409 response: duration=3ms id=d17c74c4-70a5-11e9-b4ac-79484ad3afab ip=210.23.25.246 method=GET path=/ size=659 B status=200
	May 7th 04:55:09pm INFO REPORT RequestId: 0f5ca38c-8832-448d-8eb6-f255b4b8e107        Duration: 8.55 ms       Billed Duration: 100 ms         Memory Size: 512 MB    Max Memory Used: 82 MB


Authenticated example:

	May 7th 04:54:59pm INFO staging 73c6409 request: id=cb799ba4-70a5-11e9-9b82-dd318cb7c7d8 ip=210.23.25.246 method=GET path=/
	May 7th 04:54:59pm INFO staging 73c6409 index: auth=map[ID:100571906555529103327 Name:Kai Hendry] id=cb799ba4-70a5-11e9-9b82-dd318cb7c7d8
	May 7th 04:54:59pm INFO staging 73c6409 response: duration=12ms id=cb799ba4-70a5-11e9-9b82-dd318cb7c7d8 ip=210.23.25.246 method=GET path=/ size=491 B status=
	200
	May 7th 04:54:59pm INFO REPORT RequestId: 55b7ff01-cc31-47a4-a758-fc091c79922d        Duration: 13.58 ms      Billed Duration: 100 ms         Memory Size: 51
	2 MB    Max Memory Used: 82 MB

