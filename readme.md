

# The User Management System - IS690 Summer 2024 🎉✨🔥

We will be using this repository throughout the semester.  Your job this week is to setup the continuous integration / continouous deployment (CI/CD) process between GitHub and DockerHub.  Your responsbility throughout the semester is to ensure that this deployment process is always working.  You may sometimes fail security scans and will need to fix the issues as needed. 

Watch the lecture video:

[New Lecture - IS690 Summer 2024](https://youtu.be/jEA8tPKle6k)

Old Lectures that are good for review if you didn't have IS601 in the spring:

1. [https://youtu.be/dgMCSND2FQw](Database Programming)
2. [https://youtu.be/8_BsACPtKaA](Going over implementing a new feature / user login and my account info very helpful tips)

Your homework is two parts:

1.  Link to your DockerHub repo that is hosting my project: https://hub.docker.com/r/ramyakammari/is690_summer2024

2.  Answer the following questions about the project in the following file ( Added the answers in the same file) - [here](answer.md)




## Steps to Project Setup

1. Setup the project locally
    * Fork repo to your GitHub account
    * Clone the repo to your local

2. Setup the virtual environment, we will be using the project within docker but may have instances where you want the virtual environment, since you need it for vscode to autocomplete.
    * Go into the project directory and create the virtual environment: "python3 -m venv venv"   or "python -m venv venv"
    * Activate the virtual environment "source venv/bin/activate"

2. Create a local .env file with your [MailTrap](https://mailtrap.io/) SMTP settings. Mailtrap allows you to view emails when you test the site manually. When running pytest, the system uses a Mock to simulate sending emails but doesn't actually send them.  You will need to signup for the free mailtrap account.  Check that when you register the *2nd user* that it sends a verification email.  The first user is the admin user and doesn't require email verification.

3. Run the project:
    * `docker compose up --build` <- you must have it running locally like this to run any commands.  Open up multiple terminals for other commands. press CTRL C to stop or CMD C on mac to stop
    * Set up PGAdmin at `localhost:5050` (see docker compose for login details).  You need to add the server
    * View logs for the app: `docker compose logs fastapi -f` <- do this in another window 
    * Run tests: `docker compose exec fastapi pytest`  <- try running specific tests or tests in folders i.e. `docker compose exec fastapi pytest tests/test_services`

4. Alembic:
    * When you run Pytest, it deletes the user table but doesn't remove the Alembic table. This causes Alembic to get out of sync and you won't be able to manually test the api.
    * To resolve this, drop the Alembic table and run the migration (`docker compose exec fastapi alembic upgrade head`) when you want to manually test the site through `http://localhost/docs`.
    * If you change the database schema, delete the Alembic migration, the Alembic table, and the users table. Then, regenerate the migration using the command: `docker compose exec fastapi alembic revision --autogenerate -m 'initial migration'`.
    * Since there is no real user data currently, you don't need to worry about database upgrades, but Alembic is still required to install the database tables.

5.  Dockerhub Setup:

    * Set the project up with all of the DockerHub info (dockerhub username and token) added to the production environment secret to enable the GitHub action to push to Dockerhub successfully.  *
    * Edit the .github/workflows/production.yml GitHub Action to change the Dockerhub repo on lines 76, 78, 85 from kaw393939/is690_summer2024 to your own dockerhub repo.  Once you have these, you need to work to get the repo deploying to Dockerhub by pushing to GitHub and seeing that action turns green.  

## Project General Information

Welcome to the User Management System project - an epic open-source adventure crafted by the legendary Professor Keith Williams for his rockstar students at NJIT! 🏫👨‍🏫⭐ This project is your gateway to coding glory, providing a bulletproof foundation for a user management system that will blow your mind! 🤯 You'll bridge the gap between the realms of seasoned software pros and aspiring student developers like yourselves. 


- [Introduction to the system features and overview of the project - please read](system_documentation.md) 📚
- [Project Setup Instructions](setup.md) ⚒️
- [About the Project](about.md)🔥🌟


