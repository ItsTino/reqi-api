package constants

const (
    // Rate limits (requests per minute)
    GlobalAuthLimit     = 60  // Login/Register endpoints
    GlobalRepeaterLimit = 60  // Repeater forwarding
    PublicLogLimit = 60 //Public logging
)