# Authentication

These endpoints handle user registration, login, and profile retrieval.

### `POST /api/auth/register`

  - **Description:** Registers a new user.
  - **Request Body:**
    ```json
    {
      "studentId": "string",
      "username": "string",
      "password": "string"
    }
    ```
  - **Response Body (Success):**
    ```json
    {
      "message": "Register Successful"
    }
    ```
  - **Response Body (Failure):**
    ```json
    {
      "message": "Registration failed",
      "error": "string"
    }
    ```

### `POST /api/auth/login`

  - **Description:** Logs in a user and returns a JWT token for subsequent authenticated requests.
  - **Request Body:**
    ```json
    {
      "studentId": "string",
      "password": "string"
    }
    ```
  - **Response Body (Success):**
    ```json
    {
      "token": "string",
      "user": {
        "studentId": "string",
        "username": "string"
      }
    }
    ```
  - **Response Body (Failure):**
    ```json
    {
      "message": "Authentication failed",
      "error": "string"
    }
    ```

### `GET /api/auth/me`

  - **Description:** Retrieves the profile of the currently authenticated user. Requires a valid JWT in the `Authorization` header.
  - **Headers:**
      - `Authorization: Bearer <token>`
  - **Response Body (Success):**
    ```json
    {
      "studentId": "string",
      "username": "string"
    }
    ```
  - **Response Body (Failure):**
    ```json
    {
      "message": "Unauthorized"
    }
    ```