package com.llmaiboot.bhtelegram

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    // No screenshots, screen recording or thumbnail in the recent apps list:
    // decrypted messages must not leak through the system UI.
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    super.onCreate(savedInstanceState)
  }
}
