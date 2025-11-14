import requests

token_id = "a2602a1f-127d-4fae-ba89-bdd3c29258be"
headers = {"api-key": "a2602a1f-127d-4fae-ba89-bdd3c29258be"}

r = requests.get('https://webhook.site/token/'+ token_id +'/requests?sorting=newest', headers=headers)

for request in r.json()['data']:
    print(request['url'])
