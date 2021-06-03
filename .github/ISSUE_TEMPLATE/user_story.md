---
name: User Story
about: Use this template to create user stories for the cve-services project
labels: user story, draft
assignees: mattrbianchi
---

# User Story

# Acceptance Criteria

## Scenario 1

<!--
    Scenario – In the first statement, you’ll have to write the name of the behavior that you’re describing.
    Given – The second statement refers to the beginning stage of the scenario.
    When – The third statement involves a particular action that you want the user to make.
    Then – This is used to describe the outcome of the third statement.
    And – You can use “And” to continue any statement except “Scenario.”
-->

Given:

When:

Then:

And:

# Definition of Done

There is at least one unit test per scenario, proving the expectations of the scenario have been met.

There is at least one endpoint (black box) test per scenario, proving the code fulfills the scenario with the application set up similar to its production state.
 
The openapi.yml file has been updated to document proper use of the new endpoint.  
This includes:

	- Describing how different roles can interact with the system when applicable.
	- Successful response
	- Possible error responses
