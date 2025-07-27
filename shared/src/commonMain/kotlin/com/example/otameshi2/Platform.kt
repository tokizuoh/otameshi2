package com.example.otameshi2

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform