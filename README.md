# RuralX — Citizen Services Integration Platform

RuralX is an independent civic-technology demonstration that brings citizen-service discovery, guided applications, department routing and unified tracking into one interface.

## Included capabilities

1. AI assistant with conversational, multi-turn style service guidance and natural-language need detection
2. Service/scheme recommendation from a 10-service demo catalog
3. Department mapping
4. Eligibility pre-check
5. Document checklist
6. Government API simulator
7. Connector/adapter layer with simulated responses
8. Unified application tracking
9. English, Hindi and Marathi interface labels
10. Low-bandwidth mode
11. Department Console / admin dashboard
12. Demo data and connector monitoring
13. Local issue reporting, grievances, notifications and saved-service backend
14. Secure signup/login with password hashing, OTP flow, sessions, CSRF protection and rate limiting

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## Demo admin

For local demonstration only:

- Mobile: `9999999999`
- Password: `Admin@12345`
- OTP is not required for this seeded verified demo admin account.

Change/remove the seeded demo admin before any real deployment.

## Important

RuralX does not claim to be an official government portal and does not use real government credentials or databases. Connector/API responses in this build are simulated. Official eligibility, application status and document requirements must be verified through the responsible authorized government system.

The natural-language engine is a deterministic demo classifier. A production deployment can replace it with an approved AI/NLP service while keeping verified service catalogs, human confirmation and auditable routing rules.


## v2.0.2 hotfix
- Fixed the OTP database INSERT error (`5 values for 4 columns`) that caused signup to fail after creating the account.
- Fixed/stabilized the CSRF session token behavior from v2.0.1.

### If a previous signup says the mobile number already exists
That can happen because the old bug created the user before OTP generation failed. You can either use **Login** with the same mobile/password you entered, or stop the server and delete `ruralx.db` for a fresh demo database. The server will recreate the demo admin account automatically.


## v2.1.0 AI assistant upgrade
- Reworked the home-page assistant into a conversational assistant panel with chat bubbles, quick actions and recommended services.
- Added `/api/ai/chat` for contextual responses about service selection, departments, eligibility, documents and application steps.
- Added English/Hindi/Marathi assistant responses based on the selected language.
- Added transparent confidence/matched-term information and multiple service recommendations.
- Improved result-card contrast so text is readable on the blue hero background.
- The assistant remains a deterministic local demo engine; it does not invent live government records.
