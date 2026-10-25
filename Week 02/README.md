A Contact Web Application — Week 02

A lightweight single-page contact form built with HTML5, Tailwind CSS, and Vanilla JavaScript.
Features

/contact Route: Contact form with real-time feedback.

/confirmation Route: Displays a submission receipt with status 200 OK and a unique reference ID.

Server-Side Validation: Simulates an 800ms API network request to validate inputs:

Name: Required field (non-empty).

Email: Validates format using regex (user@domain.com).

Message: Required field with a 10-character minimum.

Inline Errors: Highlights invalid fields in red with contextual error messages.

Dark Mode: Toggle button to switch between light and dark themes.
Usage

Open index.html in any web browser.

Fill out the form fields to test field validation and confirmation routing.
