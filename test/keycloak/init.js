(async () => {
    const keycloakBaseUrl = process.env.KC_URL;
    const adminUser = process.env.KC_ADMIN_USERNAME;
    const adminPassword = process.env.KC_ADMIN_PASSWORD;
    const realmName = "my-test-realm";
    const realmUrl = `${keycloakBaseUrl}/admin/realms/${realmName}`;
    const clientId = "my-test-client";

    /*
      remember to apply proper secret management for actual production uses
      do not share the secret key in public
    */
    const clientSecret = 'UTRtYkyYN1nbgdPPbBru1FDVsE8ye5JE';

    const users = [{
        username: "user",
        firstName: "John",
        lastName: "Doe",
        email: "user@example.com",
        emailVerified: true,
        enabled: true,
        credentials: [{
            type: "password",
            value: "user",
            temporary: false
        }]
    }];

    /* wrapped in a function because we may need to generate access token more than once during the setup process */
    const fetchToken = async () => {
        const tokenResponse = await fetch(`${keycloakBaseUrl}/realms/master/protocol/openid-connect/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                username: adminUser,
                password: adminPassword,
                grant_type: "password",
                client_id: "admin-cli"
            })
        });

        if (!tokenResponse.ok) {
            const { error_description } = await tokenResponse.json();
            console.error(error_description);
            process.exit(1);
        }

        return (await tokenResponse.json()).access_token;
    };

    /* wrap the access token in authorization header */
    const authorization_header = async () => {

        /* fails early if fetching the token fails, so no need to check anything */
        const access_token = await fetchToken();
        return {
            "Authorization": `Bearer ${access_token}`,
            "Content-Type": "application/json"
        };
    };

    /* --- check and create realm --- */
    await (async () => {
        const checkRealmResponse = await fetch(realmUrl, {
            method: "GET",
            headers: await authorization_header()
        });

        if (checkRealmResponse.ok) {
            console.log(`Realm '${realmName}' exists already!`);
        } else {
            const createRealmResponse = await fetch(`${keycloakBaseUrl}/admin/realms`, {
                method: "POST",
                headers: await authorization_header(),
                body: JSON.stringify({
                    realm: realmName,
                    enabled: true
                })
            });

            if (createRealmResponse.ok) {
                console.log(`Realm '${realmName}' created successfully!`);
            } else {
                const errorMessage = await createRealmResponse.json();
                console.error("Failed to create realm:", errorMessage);
                process.exit(1);
            }
        }
    })();

    /* --- check and create client --- */
    await (async () => {
        const checkClientResponse = await fetch(`${realmUrl}/clients?clientId=${clientId}`, {
            method: "GET",
            headers: await authorization_header()
        });

        const [clientInfo] = await checkClientResponse.json();

        if (checkClientResponse.ok && !!clientInfo) {
            const { secret } = clientInfo;
            console.log(`Client '${clientId}' exists already! - Client secret is - ${secret}`);
        } else {
            const clientConfig = {
                clientId: clientId,
                secret: clientSecret,
                enabled: true,
                publicClient: false,
                serviceAccountsEnabled: true,
                redirectUris: ['*'],
                attributes: {
                    'post.logout.redirect.uris': '*',
                    'oauth2.device.authorization.grant.enabled': true,
                }
            };

            const createClientResponse = await fetch(`${realmUrl}/clients`, {
                method: "POST",
                headers: await authorization_header(),
                body: JSON.stringify(clientConfig)
            });

            if (createClientResponse.ok) {
                console.log(`Client '${clientId}' created successfully!`);
            } else {
                const error_description = await createClientResponse.json();
                console.error("Failed to create client:", error_description);
                process.exit(1);
            }
        }
    })();

    /* --- check and create users --- */
    await (async () => {
        const createUser = async (newUser) => {
            const response = await fetch(`${realmUrl}/users`, {
                method: 'POST',
                headers: await authorization_header(),
                body: JSON.stringify(newUser)
            });

            if (response.status === 201) {
                console.log("User created successfully!");
            } else {
                const errorText = await response.text();
                console.error(`Failed to create user: ${response.status} ${errorText}`);
            }
        };

        await Promise.all(users.map(async (user) => {
            await createUser(user);
        }));
    })();

})();
