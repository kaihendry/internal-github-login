Example from https://github.com/dghubble/gologin/tree/master/examples/google
modifications.

When deploying in production I assume you have UP_STAGE set. I assume it is
unset locally to toggle secure cookie features, since again I assume up develop
locally with [gin](https://github.com/codegangsta/gin) on **localhost:3000**.

# .env

	export GOOGLE_CLIENT_ID=427670901447-op7f2lhfd1o6qbvri9oiisr28ltv70tl.apps.googleusercontent.com
	export GOOGLE_CLIENT_SECRET=[REDACTED]
	export SESSION_SECRET=[REDACTED]
