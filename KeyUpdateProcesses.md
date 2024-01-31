# Hard Key Reset
A hard key reset is a device publishes a new control key, followed immediately by the publication of a new DID that discards all existing communications keys.
This scenario could prevent some devices from opening communication sessions a a short duration of time until all involved devices have synchronised they control and communication keys.

# Avoiding Hard Key Resets
To avoid the side-effects of hard resets, the automatic key renewal system takes the following precautions when updating keys:
- include a random waiting time after key-aging date to avoid simultaneous key updating by multiple devices
- ensure most devices are online before updating keys
- keep communications keys valid in at least two consecutive DIDs


# Using Hard Key Resets
A user might want to trigger a hard reset if they fear some of their control or communications private keys might be compromised in the very near future, together with distrusting any lost/compromised devices
