/*
add client_secret if client authentication is enabled
*/


const keycloakBaseUrl = 'http://localhost:8090';
const realmName = "my-test-realm";
const clientId = "my-test-client";

const startDeviceFlowUrl = `${keycloakBaseUrl}/realms/${realmName}/protocol/openid-connect/auth/device`;
const tokenPollUrl = `${keycloakBaseUrl}/realms/${realmName}/protocol/openid-connect/token`;

const initialResponse = await fetch(startDeviceFlowUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
        client_id: clientId,
        scope: 'openid'
    })
});

if (!initialResponse.ok) {
    const { error_description } = await initialResponse.json();
    console.error(error_description);
    process.exit(1);
}

const initialData = await initialResponse.json();

console.log(`
            Visit this url to login: ${initialData.verification_uri} \
            
            Enter the following device code: ${initialData.user_code} \

            Or visit this url: ${initialData.verification_uri_complete} \
            `)

const checkForToken = async () => {
    return await fetch(tokenPollUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: clientId,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: initialData.device_code
        })
    });
}

const intervalId = setInterval(async () => {
    const tokenResponse = await checkForToken();
    const result = await tokenResponse.json();
    console.log(result);

    if (tokenResponse.ok) {
        clearInterval(intervalId);
    }

}, initialData.interval * 1000);