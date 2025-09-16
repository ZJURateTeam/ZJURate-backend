# Merchants 

These endpoints manage merchant-related data.

### `GET /api/merchants/`

  - **Description:** Lists all merchants available on the blockchain.
  - **Response Body (Success):** An array of merchant summaries.
    ```json
    [
      {
        "id": "string",
        "name": "string",
        "category": "string",
        "averageRating": 0.0
      }
    ]
    ```

### `GET /api/merchants/:id`

  - **Description:** Retrieves a single merchant's details, including all associated reviews.
  - **URL Parameters:**
      - `id`: The unique ID of the merchant.
  - **Response Body (Success):**
    ```json
    {
      "id": "string",
      "name": "string",
      "address": "string",
      "category": "string",
      "averageRating": 0.0,
      "reviews": [
        {
          "id": "string",
          "merchantId": "string",
          "authorId": "string",
          "rating": 0,
          "comment": "string",
          "timestamp": "string"
        }
      ]
    }
    ```
  - **Response Body (Failure):**
    ```json
    {
      "message": "Merchant not found",
      "error": "string"
    }
    ```

### `POST /api/merchants/`

  - **Description:** Creates a new merchant. Requires authentication.
  - **Headers:**
      - `Authorization: Bearer <token>`
  - **Request Body:**
    ```json
    {
      "id": "string",
      "name": "string",
      "address": "string",
      "category": "string"
    }
    ```
  - **Response Body (Success):**
    ```json
    {
      "message": "Merchant creation submitted successfully",
      "txId": "string"
    }
    ```
