import sys
import os
import unittest
import datetime

# Add the parent directory to the path to import app.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import app  # Import your Flask app

class JWKSAppTest(unittest.TestCase):
    def setUp(self):
        # Initialize the database and add test keys
        app.init_db()

        # Insert an expired key and a valid key for testing
        expired_time = int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp())
        valid_time = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
        
        app.save_key(app.generate_private_key(), expired_time)
        app.save_key(app.generate_private_key(), valid_time)

        # Insert a test user
        with app.get_db() as conn:
            conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                         ("testuser", app.ph.hash("testpassword"), "test@example.com"))
            conn.commit()

    def test_auth_unexpired_key(self):
        with app.app.test_client() as client:
            response = client.post('/auth', json={
                "username": "testuser",
                "password": "testpassword"
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn('token', response.json)
            self.assertTrue(isinstance(response.json['token'], str))

    def test_auth_expired_key(self):
        with app.app.test_client() as client:
            response = client.post('/auth?expired=true', json={
                "username": "testuser",
                "password": "testpassword"
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn('token', response.json)
            self.assertTrue(isinstance(response.json['token'], str))

    def test_no_keys_in_database(self):
        with app.get_db() as conn:
            conn.execute("DELETE FROM keys")
            conn.commit()
        with app.app.test_client() as client:
            response = client.post('/auth', json={
                "username": "testuser",
                "password": "testpassword"
            })
            self.assertEqual(response.status_code, 404)

    def test_jwks_route(self):
        with app.app.test_client() as client:
            response = client.get('/.well-known/jwks.json')
            self.assertEqual(response.status_code, 200)
            self.assertIn("keys", response.json)
            self.assertTrue(len(response.json["keys"]) > 0)
            for key in response.json["keys"]:
                self.assertIn("kid", key)
                self.assertIn("kty", key)
                self.assertIn("use", key)
                self.assertIn("alg", key)
                self.assertIn("n", key)
                self.assertIn("e", key)

    def test_auth_rate_limit(self):
        with app.app.test_client() as client:
            for _ in range(3):  # Send 3 requests quickly to exceed the 2/sec limit
                response = client.post('/auth', json={
                    "username": "testuser",
                    "password": "testpassword"
                })
            self.assertEqual(response.status_code, 429)  # After limit exceeded, expect 429

if __name__ == '__main__':
    unittest.main()
