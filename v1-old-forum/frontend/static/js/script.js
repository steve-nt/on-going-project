/*
 * Forum Frontend JavaScript - Main Script
 * This file handles interactive features for the forum homepage
 * Learn about DOM manipulation: https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model
 * Learn about event handling: https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener
 */

// FEATURE 1: Close category details dropdown when clicking outside
// This provides better UX by automatically closing dropdowns when users click elsewhere
// The "click" event bubbles up from the clicked element to the document
// Learn about event bubbling: https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Building_blocks/Events#event_bubbling_and_capture
document.addEventListener("click", function (event) {
  // Find the category details element (likely a <details> HTML element)
  // querySelector returns the first element matching the CSS selector
  // Learn about querySelector: https://developer.mozilla.org/en-US/docs/Web/API/Document/querySelector
  const details = document.querySelector(".category-details");

  // Guard clause: if no details element exists, exit early
  // This prevents errors when the element doesn't exist on the current page
  if (!details) return;

  // Check if the clicked element is OUTSIDE the details dropdown
  // contains() returns true if the element contains the target (including itself)
  // event.target is the actual element that was clicked
  // Learn about event.target: https://developer.mozilla.org/en-US/docs/Web/API/Event/target
  if (!details.contains(event.target)) {
    // Close the dropdown by removing the "open" attribute
    // For <details> elements, the "open" attribute controls visibility
    // Learn about details element: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/details
    details.removeAttribute("open");
  }
});

// FEATURE 2: Highlight active navigation button based on current page
// This improves navigation UX by showing users which page they're currently on
// The DOMContentLoaded event fires when HTML is fully loaded and parsed
// Learn about DOMContentLoaded: https://developer.mozilla.org/en-US/docs/Web/API/Document/DOMContentLoaded_event
document.addEventListener("DOMContentLoaded", function () {
  // Find all navigation buttons with the specified CSS class
  // querySelectorAll returns a NodeList (array-like) of all matching elements
  // Learn about querySelectorAll: https://developer.mozilla.org/en-US/docs/Web/API/Document/querySelectorAll
  const buttons = document.querySelectorAll(".nav-categories-btn");

  // Get the current page path from the browser's location
  // pathname includes the path after the domain (e.g., "/categories", "/topics")
  // Learn about window.location: https://developer.mozilla.org/en-US/docs/Web/API/Location
  const path = window.location.pathname;

  // Iterate through each navigation button
  // forEach is a modern way to loop through array-like objects
  // Learn about forEach: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/forEach
  buttons.forEach((button) => {
    // First, remove "active" class from all buttons (reset state)
    // classList provides methods to manipulate CSS classes
    // Learn about classList: https://developer.mozilla.org/en-US/docs/Web/API/Element/classList
    button.classList.remove("active");

    // Check if this button's href matches the current page path
    // getAttribute gets the value of the specified HTML attribute
    // Learn about getAttribute: https://developer.mozilla.org/en-US/docs/Web/API/Element/getAttribute
    if (button.getAttribute("href") === path) {
      // Add "active" class to highlight the current page button
      // This will trigger CSS styling to visually indicate the active state
      button.classList.add("active");
    }
  });
});

/*
 * FUTURE ENHANCEMENTS:
 * This script could be extended with additional features:
 *
 * 1. API Integration:
 *    - Fetch topics dynamically with AJAX
 *    - Handle form submissions for login/register
 *    - Real-time updates with WebSockets
 *
 * 2. User Interactions:
 *    - Search functionality
 *    - Topic creation modal
 *    - Comment management
 *
 * 3. Performance:
 *    - Debounced search input
 *    - Lazy loading for long topic lists
 *    - Client-side caching
 *
 * Learn about modern JavaScript: https://javascript.info/
 * Learn about web APIs: https://developer.mozilla.org/en-US/docs/Web/API
 */
