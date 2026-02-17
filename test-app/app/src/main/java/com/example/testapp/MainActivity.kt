package com.example.testapp

import android.os.Bundle
import android.app.Activity
import android.widget.TextView

class MainActivity : Activity() {

    // Fake API keys for testing the analyzer plugin
    companion object {
        const val AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
        const val AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        const val FIREBASE_API_KEY = "AIzaSyDemoKey123456789abcdefghijklmnop"
        const val STRIPE_API_KEY = "sk_live_51MzQ2ExampleStripeKey123456789"
        const val GOOGLE_MAPS_KEY = "AIzaSyBH4ExampleGoogleMapsKeyXYZ789"
        const val GENERIC_API_KEY = "api_key=abc123xyz789def456ghi012jkl345"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val textView = TextView(this)
        textView.text = getString(R.string.hello_world)
        setContentView(textView)

        // Example usage of the keys (for demonstration purposes)
        initializeServices()
    }

    private fun initializeServices() {
        // These are hardcoded for demo - in production use secure storage
        val awsKey = AWS_ACCESS_KEY
        val firebaseKey = FIREBASE_API_KEY

        // Configuration with various API endpoints
        configureApiClient(GENERIC_API_KEY)
    }

    private fun configureApiClient(apiKey: String) {
        // API client configuration
        val config = mapOf(
            "endpoint" to "https://api.example.com",
            "apiKey" to apiKey,
            "timeout" to 30000
        )
    }

    // Additional method with another API key pattern
    private fun setupPaymentGateway() {
        val stripeKey = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
        processPayment(stripeKey)
    }

    private fun processPayment(key: String) {
        // Payment processing logic would go here
    }
}
