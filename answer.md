# Answer These Questions Here, you can add additional pages to answer questions, just link to them so that I can view these questions and see your answer or the link(s) to your answer.

## FastAPI and Pydantic

1. **What role does Pydantic play in FastAPI, and how does it enhance data validation and settings management?**
Pydantic is a data validation and settings management library used in FastAPI to enforce type constraints and validate incoming request data. It enables the automatic validation and serialization of request payloads, ensuring that the data conforms to the expected types and structures. This enhances the reliability and security of the API.

**Example from the project:**
All of our API payloads are defined using pydantic. All our schemas have been created as classes inherited from the pydantic basemodel. [schemas](https://github.com/RamyaKammari/is690_summer2024/tree/main/app/schemas) folder conatins all the API payload/schemas defined for our project.

few exaples from the above folder are:

- Schema for the create user API [UserCreate](https://github.com/RamyaKammari/is690_summer2024/blob/main/app/schemas/user_schemas.py#L20C1-L39C1)


```python
class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: UserRole

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
 
    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")
```

- Schema for updating an Event [EventUpdate](https://github.com/RamyaKammari/is690_summer2024/blob/main/app/schemas/event_schema.py#L34-L41)

```python
class EventUpdate(EventBase):
    title: Optional[str] = Field(None, example="Updated Company Tour")
    description: Optional[str] = Field(None, example="An updated description of the company tour.")
    start_datetime: Optional[datetime] = Field(None, example="2023-06-02T10:00:00")
    end_datetime: Optional[datetime] = Field(None, example="2023-06-02T12:00:00")
    published: Optional[bool] = Field(None, example=False)
    event_type: Optional[EventType] = Field(None, example=EventType.GUEST_LECTURE)

```

2. **Outline the complete process of handling a user login request in your FastAPI application. Provide a step-by-step explanation with code examples from the project.**

The user login process involves the following steps:

- The user visits the login page at `http://localhost:8000/login-form`.
- The login page is displayed with a form where the user can fill in their email ID and password.

```python
@router.get("/login-form", include_in_schema=False)
async def login_form(request: Request):
      return templates.TemplateResponse("login.html", {"request": request})
```
- Once the user fills in the details and submits the form, a POST request is made to the /login_with_form/ endpoint with the login details.
- The backend handles the login process by validating the user's credentials, generating an access token, and setting a cookie with the token.
```python
@router.post(
        "/login_with_form/", 
        include_in_schema=False, tags=["Login and Registration"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db)
    ):
    try:
        user = await UserService.login_user(session, form_data.username, form_data.password)
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name), "user_id": str(user.id)},
            expires_delta=access_token_expires
        )
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="access_token", value=access_token, httponly=True)
        return response
    except InvalidCredentialsException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except AccountLockedException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
```


3. **Explain the service repository pattern and how it is applied in your project. Provide an example of how routes are managed and linked to services.**

The service repository pattern is a design pattern that separates the data access logic (repository) from the business logic (service). This separation of concerns helps to create a more modular, maintainable, and testable codebase. We have followed the similar structure.

In our project, we have routes directory, which contains methods for handliling each api end point. And in the router, we have implemented high level business logic by abstracting out the data access or db interactions to a seperate python modules by implementing appropriate services.

Example:
Implementation of Get User API
```python
@router.get(
            "/users/{user_id}", 
            response_model=UserResponse, name="get_user", 
            tags=["User Management Requires (Admin or Manager Roles)"])
async def get_user(
    user_id: UUID, 
    request: Request, 
    db: AsyncSession = Depends(get_db), 
    token: str = Depends(oauth2_scheme), 
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))):
    try:
        user = await UserService.get_by_id(db, user_id)
        return UserResponse.model_construct(
            id=user.id,
            nickname=user.nickname,
            first_name=user.first_name,
            last_name=user.last_name,
            bio=user.bio,
            profile_picture_url=user.profile_picture_url,
            github_profile_url=user.github_profile_url,
            linkedin_profile_url=user.linkedin_profile_url,
            role=user.role,
            email=user.email,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
            links=create_user_links(user.id, request)  
        )
    except UserNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
```
from the above [router code](https://github.com/RamyaKammari/is690_summer2024/blob/main/app/routers/user_routes.py#L25-L54). we can observe that for retriving the details of the user from the database, we just called the get_by_id method. And the actual implementation of getting the user details from the DB is done in a seperate module [user_service.py](https://github.com/RamyaKammari/is690_summer2024/blob/main/app/services/user_service.py#L28-L33).

```python
    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> User:
        user = await cls._fetch_user(session, id=user_id)
        if not user:
            raise UserNotFoundException(f"User with ID {user_id} not found.")
        return user
```

## Database Management with Alembic and SQLAlchemy

4. **How does Alembic manage database migrations, and why is this important for maintaining database schemas?**
Alembic manages database migrations by generating migration scripts that reflect changes in the database schema. This is important for maintaining consistency and versioning of the database schema over time, ensuring that all changes are tracked and can be applied or reverted as needed.
For each Schema change in the Database, It will create a version file, which contains the script used for the migration in the functions upgrade() and downgrade()

Example migration script generated by the Albemic: https://github.com/RamyaKammari/is690_summer2024/blob/main/alembic/versions/6b62f34b7189_initial_migration.py

## Pytest

5. **Why is Pytest critical for the development of the API?**
Pytest is a powerful testing framework that is widely used for writing simple as well as scalable test cases. It is very critical for API development because helps ensure that the API behaves as expected and that changes or additions do not break existing functionality. We can write test cases on our services and modules which can be configured to run after code changes to do the regression testing and caught bugs if any well before. This leads to higher code quality and more reliable software.

## JWT and User Authentication

6. **Explain the functioning of JWT (JSON Web Tokens) in user authentication. How are JWTs generated, encoded, and used within the project?**
JWTs are used to securely transmit information between parties as a JSON object. They are used for authentication by generating a token that includes encoded user information. This token is then sent with each request to verify the user's identity.

code snippets from our project using the JWT tokens:

- JWT token generation:
```python
def create_access_token(*, data: dict, expires_delta: timedelta = None):
    logging.debug(f"Starting token creation. Data: {data}")
    to_encode = data.copy()
    
    # Convert 'role' to uppercase before encoding the JWT, if present
    if 'role' in to_encode:
        to_encode['role'] = to_encode['role'].upper()
        logging.debug(f"'role' modified to uppercase: {to_encode['role']}")
    
    # Check for required fields in the token payload
    if 'user_id' not in to_encode:
        logging.error("Missing 'user_id' in token payload")
        raise ValueError("user_id is required in the token payload")
    
    # Set the expiration time for the token using timezone-aware datetime
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire.timestamp()})  # Store as timestamp
    logging.debug(f"Token expiration set to {expire.isoformat()}")
    
    # Encode the JWT
    try:
        encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
        logging.info(f"JWT created with expiration at {expire.isoformat()}")
        logging.debug(f"Encoded JWT: {encoded_jwt}")
        
        # Immediate decoding test to verify correctness right after creation
        try:
            decoded = jwt.decode(encoded_jwt, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            logging.info("Immediate decode result: {}".format(decoded))
            logging.debug("Immediate decode check: {}".format(decoded))
        except jwt.ExpiredSignatureError:
            logging.error("Token already expired upon creation, check system clock.")
        except jwt.InvalidTokenError as e:
            logging.error(f"Token invalid right after creation: {e}")
        except jwt.PyJWTError as e:
            logging.error(f"Error during immediate token decode: {e}")
        
        return encoded_jwt
    except Exception as e:
        logging.error(f"Error encoding JWT: {e}")
        raise
```

- JWT token decode
```python
def decode_token(token: str):
    logging.info(f"Attempting to decode token: {token}")
    try:
        decoded = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        logging.info("JWT decoded successfully")
        logging.debug(f"Decoded JWT payload: {decoded}")
        
        # Comparing timestamps using UTC now
        current_timestamp = datetime.now(timezone.utc).timestamp()
        exp_timestamp = decoded.get("exp")
        
        logging.info(f"Current timestamp: {current_timestamp}")
        logging.info(f"Token expiration timestamp: {exp_timestamp}")
        
        if current_timestamp > exp_timestamp:
            logging.warning("Token has expired.")
            return None
        
        return decoded
    except jwt.ExpiredSignatureError:
        logging.warning("Attempt to access with expired token.")
        return None
    except jwt.InvalidTokenError:
        logging.error("Invalid token detected.")
        return None
    except jwt.PyJWTError as e:
        logging.error(f"JWT decoding failed: {e}")
        return None
```

- Usgae: When a user logins, we create a jwt token and set it as a cookiee, which can be used for further verifications.
```python
@router.post("/login/",
             response_model=TokenResponse, 
             tags=["Login and Registration"]
             )
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db)
    ):
    try:
        user = await UserService.login_user(session, form_data.username, form_data.password)
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name), "user_id": str(user.id)},
            expires_delta=access_token_expires
        )
        # Immediately decode to verify
        try:
            decoded = jwt.decode(access_token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            logging.info(f"Immediate decode check: {decoded}")
        except jwt.PyJWTError as e:
            logging.error(f"Immediate decode failed: {e}")
        
        return {"access_token": access_token, "token_type": "bearer"}
    except InvalidCredentialsException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except AccountLockedException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
```

7. **Decode the following JWT and explain its contents:**
   - Token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsInJvbGUiOiJBRE1JTiIsInVzZXJfaWQiOiJjZGY4M2QzZi0zNzQ5LTRjZGQtOTRlYS1hNTVjZmMwNDhkMGYiLCJleHAiOjE3MTc2MTY4MjAuMjIwNzA5fQ.ANS8PgUiwPCmOvnZLYTCy_5WzLyhCDOx8aF4xu-Kaz8`
   - Use [jwt.io](https://jwt.io/) to decode and explain the contents.
Decoded payload using jwt.io:
```
-- headers
{
  "alg": "HS256",
  "typ": "JWT"
}

-- payload
{
  "sub": "john.doe@example.com",
  "role": "ADMIN",
  "user_id": "cdf83d3f-3749-4cdd-94ea-a55cfc048d0f",
  "exp": 1717616820.220709
}
```

8. **Describe the user registration logic in your project. Provide a pseudo-code workflow from the registration request to storing the user in the database.**

The user registration process in the project involves several steps, from receiving the registration request to storing the user information in the database. 

#### High level steps
   - The client sends a POST request with the user's registration details to the `/register/` endpoint.
   - The input data is validated to ensure it meets the required format and constraints.
   - The system checks if a user with the provided email already exists in the database.
   - The user's password is hashed for secure storage.
   - A unique nickname is generated for the new user.
   - The user is assigned a role (e.g., ADMIN or ANONYMOUS) based on certain conditions.
   - A verification token is generated for the user.
   - The new user's information is stored in the database.
   - A verification email is sent to the user.
    - A response is returned to the client with the user's details.

#### Pseudo code
```
Function register_form(request):
    Render the registration form

Function register(user_data, session, email_service):
    Try:
        Validate user_data against UserCreate schema
        Check if a user with the given email exists in the database
        If user exists:
            Raise EmailAlreadyExistsException
        
        Hash the password from user_data
        Generate a unique nickname
        Count the number of users in the database
        If user count is zero:
            Set role to ADMIN and email_verified to True
        Else:
            Set role to ANONYMOUS
        
        Generate a verification token
        Create a new user with validated and processed data
        Add new user to database session
        Commit the transaction
        
        Send a verification email with the verification token
        Return the registered user's information
    Except ValidationError:
        Raise validation error
```

#### code snippets from our project
```python

# ui_routes.py
@router.get("/register-form", include_in_schema=False)
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

#user_routes.py
@router.post(
        "/register/", 
        response_model=UserResponse, 
        tags=["Login and Registration"]
        )
async def register(
    user_data: UserCreate = Body(...), 
    session: AsyncSession = Depends(get_db), 
    email_service: EmailService = Depends(get_email_service)):
    try:
        user = await UserService.register_user(session, user_data.model_dump(), email_service)
        return UserResponse.model_construct(
            nickname=user.nickname,
            first_name=user.first_name,
            last_name=user.last_name,
            bio=user.bio,
            profile_picture_url=user.profile_picture_url,
            github_profile_url=user.github_profile_url,
            linkedin_profile_url=user.linkedin_profile_url,
            role=user.role,
            email=user.email,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )
    except EmailAlreadyExistsException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
# user_service.py
@classmethod
async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> User:
   return await cls.create(session, user_data, email_service)


@classmethod
async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> User:
   try:
      validated_data = UserCreate(**user_data).model_dump()
      existing_user = await cls.get_by_email(session, validated_data['email'])
      if existing_user:
            raise EmailAlreadyExistsException("User with given email already exists.")
      
      validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
      new_user = User(**validated_data)
      new_nickname = generate_nickname()
      while await cls.get_by_nickname(session, new_nickname):
            new_nickname = generate_nickname()
      new_user.nickname = new_nickname
      user_count = await cls.count(session)
      new_user.role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS            
      if new_user.role == UserRole.ADMIN:
            new_user.email_verified = True

      
      new_user.verification_token = generate_verification_token()
      session.add(new_user)
      await session.commit()
      await email_service.send_verification_email(new_user)
      return new_user
   except ValidationError as e:
      raise e

```

9. **Detail the steps involved in the user email verification process. Provide a pseudo-code workflow from sending a verification email to activating the user's account.**
The email verification process in our project ensures that users can verify their account's email address before gaining full access to certain functionalities. The process involves sending a verification email with a unique link, and upon clicking the link, verifying the user’s email and updating their account status. Below is the detailed pseudo-code workflow describing each step of the email verification process.

```
Function send_verification_email(user):
    Generate verification_url with user.id and user.verification_partner
    Prepare email data with user's first name, verification_url, and user.email
    Send email using the send_user_email function with 'email_verification' type

Function verify_email(user_id, token, db):
    Try:
        user = GetUserById(db, user_id)
        If user is None:
            Raise UserNotFoundException
        If user.verification_token != token:
            Raise InvalidVerificationTokenException

        user.email_verified = True
        user.verification_token = None
        If user.role == ANONYMOUS:
            user.role = AUTHENTICATED

        SaveChanges(db, user)
        Redirect to account verification confirmation page
    Except exceptions as e:
        Handle exceptions (e.g., invalid token, user not found)

Function send_user_email(user_data, email_type):
    Determine subject based on email_type
    Render email HTML content using a template manager
    Send email via SMTP client
```

code snippets from our project

```python
async def send_user_email(self, user_data: dict, email_type: str):
      subject_map = {
         'email_verification': "Verify Your Account",
         'password_reset': "Password Reset Instructions",
         'account_locked': "Account Locked Notification"
      }

      if email_type not in subject_map:
         raise ValueError("Invalid email type")

      html_content = self.template_manager.render_template(email_type, **user_data)
      self.smtp_client.send_email(subject_map[email_type], html_content, user_data['email'])

async def send_verification_email(self, user: User):
   verification_url = f"{settings.server_base_url}verify-email/{user.id}/{user.verification_token}"
   await self.send_user_email({
      "name": user.first_name,
      "verification_url": verification_url,
      "email": user.email
   }, 'email_verification')


@router.get("/verify-email/{user_id}/{token}", status_code=status.HTTP_200_OK, name="verify_email", tags=["Login and Registration"])
async def verify_email(user_id: UUID, token: str, db: AsyncSession = Depends(get_db), email_service: EmailService = Depends(get_email_service)):
    try:
        await UserService.verify_email_with_token(db, user_id, token)
        return RedirectResponse(url=settings.account_verfiy_destination)
    except InvalidVerificationTokenException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except UserNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

@classmethod
async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> None:
   user = await cls.get_by_id(session, user_id)
   if user is None or user.verification_token != token:
      raise InvalidVerificationTokenException("Invalid or expired verification token")
   
   user.email_verified = True
   user.verification_token = None  # Clear the token once used
   if user.role == UserRole.ANONYMOUS:
      user.role = UserRole.AUTHENTICATED
   session.add(user)
   await session.commit()
   return True
```

## Security Practices

10. **How do you ensure the security of user passwords in your project? Discuss the hashing algorithm used and any additional security measures implemented.**
the security of user passwords is ensured through the use of the bcrypt hashing algorithm, which is designed to be computationally expensive to defend against brute-force attacks. Here’s a detailed breakdown of how bcrypt is used and the additional security measures implemented:

#### Hashing Algorithm: bcrypt
- bcrypt Usage: In the hash_password function, bcrypt is utilized to hash passwords with a specified cost factor (rounds). This cost factor is a key aspect of bcrypt that allows us to increase the computation time required to hash passwords, thereby enhancing security by making it more difficult for attackers to use brute force or rainbow table attacks.
- Salting: bcrypt inherently uses a salt (a random value added to the password before hashing) to ensure that two identical passwords will result in different hashes. This prevents attackers from easily using precomputed tables (rainbow tables) to crack the hashes.
- Configurable Cost Factor: The cost factor can be adjusted by changing the rounds parameter. This flexibility allows the security to be scaled with advances in hardware capabilities, maintaining a high level of protection against unauthorized access.

#### Additional Security Measures:
- Secure Password Storage: The hashed passwords, along with their unique salts, are securely stored in the database. This storage strategy ensures that even if the database is compromised, the actual passwords remain protected due to the difficulty of reversing the bcrypt hashes.
- Password Verification: When a user logs in, the verify_password function checks the provided password against the stored hash using bcrypt’s check mechanism. This process is secure because it uses the same salt and cost factor that were used when the password was originally hashed.
- Secure Token Generation: The generate_verification_token function uses secrets.token_urlsafe to generate a secure token for email verification processes. This method ensures that the tokens are unpredictable and resistant to guessing attacks, which is crucial for operations like account verification and password resets.
- JWT and Role Based Access managment: JWT tokens are securely generated and transmitted after user registration or login, encapsulating user roles for access control and containing expiration times for enhanced security. They are stored using HTTP-only cookies and come with mechanisms for token refresh and revocation to maintain authentication integrity and prevent unauthorized access.

11. **Explain the difference between hashing and encoding. Provide examples from your project where each is used:**
    - **Hashing:** Example and explanation with code
    - **Encoding:** Example and explanation with code
### Hashing
Hashing is a process used to transform data into a fixed-size hash value or hash code, which is typically used for security purposes. It is a one-way function, meaning the original data cannot be retrieved from the hash value. When a user enters their password, We can hash it and compare with the hash we have to verify the user, but it is impossible to retrieve the password of the user from the hash.

Example from the project:
In the project, we use bcrypt for hashing passwords. The hash_password function hashes user passwords before they are stored in the database to ensure that actual passwords are not stored, enhancing security.
```python
def hash_password(password: str, rounds: int = 12):
   salt = bcrypt.gensalt(rounds=rounds)
   hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
   return hashed_password.decode('utf-8')
```

### Encoding
Encoding is the process of converting data from one form to another to ensure it is compatible with different systems or mediums. Unlike hashing, encoding is reversible, allowing the original data to be retrieved if needed. It's often used to convert binary data to a readable or transferable format.

Example from the project:
JWT tokens in the project are encoded to securely transfer user information over networks. The JWT library encodes user information, including roles and permissions, into a token format that is both secure and easily transmitted.

```python
# jwt_service.py
# encoding snippet
encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
logging.info(f"JWT created with expiration at {expire.isoformat()}")
logging.debug(f"Encoded JWT: {encoded_jwt}")
        
# Decoding snippet
decoded = jwt.decode(encoded_jwt, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
logging.info("Immediate decode result: {}".format(decoded))
logging.debug("Immediate decode check: {}".format(decoded))
```
## Project Management with Docker and CI/CD

12. **Discuss the advantages of using Docker Compose for running your project. How does it help in maintaining a consistent development and deployment environment?**
Docker Compose is a powerful tool for defining and running multi-container Docker applications. By using a YAML file to configure your application’s services, networks, and volumes, Docker Compose allows you to orchestrate these containers with simple commands.

Docker Compose helps maintain a consistent development and deployment environment by ensuring that every team member, regardless of their operating system or development tools, uses the same container configurations. This consistency extends from development through to production, eliminating the common problem of discrepancies between environments that can lead to bugs and deployment issues. By defining services, networks, and volumes in a single docker-compose.yml file, Docker Compose ensures that the application runs the same way everywhere, reducing the chances of encountering "it works on my machine" problems and making it easier to manage and scale applications across different stages of the development lifecycle.


13. **Describe the role of GitHub Actions in your project's CI/CD pipeline. How do you automate testing and deployment using GitHub Actions?**
Github Actions acts as the automation framework for automated testing and docker image deplyment in our project. This ensures that your code is consistently tested and deployed, reducing manual effort and minimizing errors.

Here is how it is accomplished in our setup:

#### Continuous Integration (CI)
Automated Testing: When changes are pushed to the main branch or when a pull request targeting the main branch is created, the GitHub Actions workflow triggers automatically. The test job sets up a virtual environment on Ubuntu, installs the required Python version and dependencies, and then runs unit tests using Pytest. This ensures that all new or changed code is tested against a PostgreSQL database configured exactly as it would be in a production-like environment.

#### Continuous Deployment (CD)
Automated Deployment: Upon successful completion of the tests, the workflow transitions to the build-and-push-docket job. This job is dependent on the success of the test job, ensuring that only code that has passed all tests can move on to this stage.
Docker Image Creation and Push: The code that passed the tests is used to build a Docker image, which is then tagged with the name of the branch and pushed to DockerHub. This is done using Docker Buildx for multi-platform compatibility, which is crucial for ensuring that the application runs smoothly across different systems.
Docker Image Scanning: After the image is pushed to DockerHub, it is scanned for vulnerabilities with Trivy. The job is configured to fail if any critical or high-severity vulnerabilities are found, thus preventing insecure or potentially harmful code from being deployed.

## API Design and Implementation

14. **What are REST APIs, and how do they function in your project? Provide an example of a REST endpoint from your user management system.**
REST APIs, or Representational State Transfer APIs, are a set of rules and standards that allow for the creation of web services. They use HTTP methods such as GET, POST, PUT, DELETE, and others to perform CRUD (Create, Read, Update, Delete) operations on resources.

We use REST APIs to interact with backend to achieve our usecases. In our Project we have used multiple REST APIs for creating, updating, deleting and fetching the user details and also the event details.

All the rest APIs are defined in the [routers](https://github.com/RamyaKammari/is690_summer2024/tree/main/app/routers) folder for our project.

-  We have GET, PUT, POST, DELETE apis implemented for event management and also user management.

An example REST endpoint from the user management:

```python
@router.get(
            "/users/{user_id}", 
            response_model=UserResponse, name="get_user", 
            tags=["User Management Requires (Admin or Manager Roles)"])
async def get_user(
    user_id: UUID, 
    request: Request, 
    db: AsyncSession = Depends(get_db), 
    token: str = Depends(oauth2_scheme), 
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))):
    try:
        user = await UserService.get_by_id(db, user_id)
        return UserResponse.model_construct(
            id=user.id,
            nickname=user.nickname,
            first_name=user.first_name,
            last_name=user.last_name,
            bio=user.bio,
            profile_picture_url=user.profile_picture_url,
            github_profile_url=user.github_profile_url,
            linkedin_profile_url=user.linkedin_profile_url,
            role=user.role,
            email=user.email,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
            links=create_user_links(user.id, request)  
        )
    except UserNotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
```
This is a GET REST API which returns you the user details given the user id.

15. **What is HATEOAS (Hypermedia as the Engine of Application State)? Provide an example of its implementation in your project's API responses, along with a screenshot.**
HATEOAS (Hypermedia as the Engine of Application State) is a principle used in RESTful APIs that enables clients to dynamically navigate between the different functionalities of the API using hypermedia links provided in the responses. This approach allows clients to discover actions available to them directly through API responses, making the API more flexible and easier to integrate with, as clients don't need to hard-code URLs or understand the API's structure in advance.

Implementations examples from our project:
<img width="958" alt="Screenshot 2024-06-12 at 3 10 00 AM" src="https://github.com/RamyaKammari/is690_summer2024/assets/123509204/e4713c47-e570-4f57-93d0-f9897694d23c">


## Role-Based Access Control (RBAC)

16. **What is Role-Based Access Control (RBAC) and how is it implemented in your project?**

17. **Explain the different user roles defined in your project (ANONYMOUS, AUTHENTICATED, MANAGER, ADMIN) and their permissions.**

18. **Provide a code example showing how RBAC is enforced in one of your FastAPI endpoints.**

## Route Parameters and Pydantic Schemas

19. **Explain how route parameters are used in FastAPI. Provide an example of a route that takes a parameter and demonstrate how it is used within the endpoint.**

20. **How does FastAPI use Pydantic schemas to generate Swagger documentation? Provide an example from your project where a Pydantic schema is used and show the corresponding Swagger documentation.**

These questions ensure a comprehensive assessment of the students' understanding of the topics related to your project setup, focusing on practical implementations and theoretical concepts.
