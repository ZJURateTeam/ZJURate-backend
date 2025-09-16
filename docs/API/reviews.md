# Reviews 

These endpoints handle the submission and retrieval of reviews.

### `POST /api/reviews/`

  - **Description:** Submits a new review for a merchant. Requires authentication.
  - **Headers:**
      - `Authorization: Bearer <token>`
  - **Request Body:**
    ```json
    {
      "merchantId": "string",
      "rating": 0,
      "comment": "string",
      "imageHash": "string"
    }
    ```
  - **Response Body (Success):**
    ```json
    {
      "message": "Review submitted successfully, waiting for blockchain confirmation",
      "txId": "string"
    }
    ```

### `GET /api/reviews/my`

  - **Description:** Fetches all reviews submitted by the currently authenticated user.
  - **Headers:**
      - `Authorization: Bearer <token>`
  - **Response Body (Success):** An array of reviews.
    ```json
    [
      {
        "id": "string",
        "merchantId": "string",
        "authorId": "string",
        "rating": 0,
        "comment": "string",
        "timestamp": "string"
      }
    ]
    ```