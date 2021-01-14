# LeapTrace
LeapTrace is an x64dbg plugin that aims to accelerate tracing by disassembling instructions, and then place a breakpoint at the next branch instruction. This will lower the number of context switches and improve performance.

Currently LeapTrace freezes the x64dbg GUI so it should not be used in production.

## Usage

``leapinto``: run to the next branch instruction.

``leapover``: run to the next branch instruction but don't step in calls.

``leapintoconditional condition, [maxsteps]``: run until condition is met at a branch instruction or until maxsteps is reached.

``leapoverconditional condition, [maxsteps]``: run until condition is met at a branch instruction or until maxsteps is reached, but don't step in calls.

LeapTrace supports x64dbg tracing. Enable run trace or trace record if you need them.

## Licence

LeapTrace is released under the GPLv3 licence.
