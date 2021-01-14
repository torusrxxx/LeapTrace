#include "plugin.h"
#include "zydis_wrapper.h"
size_t buffersize = 4096;
unsigned char* data;
Zydis dis;
bool useHardware = true; //There is a bug that "run to cursor" cannot be used to run the loop once more, but it just stucks there.
char* tracecondition = NULL;
int maxcount = 50000;
int tracecount = 0;
duint lastExpectedCIP;
bool(*tracepredicate)() = NULL;

duint Leap(bool (*predicate)())
{
    REGDUMP regdump;
    duint cip;
    duint offset = 0;
    char traceexecute[32];
    bool usetraceexecute;
    if (!DbgGetRegDumpEx(&regdump, sizeof(regdump)))
        return 0; //???
    cip = regdump.regcontext.cip;
    if (!DbgMemRead(cip, data, buffersize))
        return cip;
    
    // First instruction
    if (!dis.Disassemble(cip, data, 16))
        return cip;
    if (!dis.IsNop() && (predicate() || dis.IsInt3() || dis.IsRet() || dis.IsUnusual()))
    {
        if (dis.IsInt3())
            return cip;
        // We are at a branch instruction, probably we have leaped previously, so we skip to destination and continue there.
        if (dis.IsBranchGoingToExecute(regdump.regcontext.eflags, regdump.regcontext.ccx))
        {
            cip = DbgGetBranchDestination(cip);
            if (!DbgMemRead(cip, data, buffersize))
                return cip;
        }
        else
            offset = dis.GetInstr()->length;
    }
    else
        offset = dis.GetInstr()->length;
    // Is trace record enabled?
    sprintf_s(traceexecute, "tr.enabled(%p)", cip + offset);
    usetraceexecute = DbgValFromString(traceexecute) != 0;
    if (usetraceexecute)
        memcpy(traceexecute, "traceexecute ", 13);
    // Follow next instructions until condition
    do
    {
        if (!dis.Disassemble(cip + offset, data + offset, 16))
            break;
        if (!dis.IsNop() && (predicate() || dis.IsInt3() || dis.IsRet() || dis.IsUnusual()))
            break;
        // Fill in trace record
        if (usetraceexecute)
        {
            sprintf_s(traceexecute + 13, sizeof(traceexecute) - 13, "%p", cip + offset);
            DbgCmdExecDirect(traceexecute);
        }
        offset += dis.GetInstr()->length;
        if (offset + 16 >= buffersize)
            break;
    } while (true);
    return cip + offset;
}

bool LeapToward(duint addr)
{
    char cmd[64];
    lastExpectedCIP = addr;
    if (useHardware)
    {
        // Leap using singleshoot hardware breakpoint
        sprintf_s(cmd, "bph %p", addr);
        if (!DbgCmdExecDirect(cmd))
            return false;
        sprintf_s(cmd, "SetHardwareBreakpointSingleshoot %p, 1", addr);
        if (!DbgCmdExecDirect(cmd))
            return false;
        return DbgCmdExecDirect("run");
    }
    else
    {
        // Leap using "run to cursor"
        sprintf_s(cmd, "run %p", addr);
        return DbgCmdExecDirect(cmd);
    }
}

bool LeapIntoCond()
{
    return dis.IsCall() || dis.IsJump() || dis.IsLoop();
}

bool LeapOverCond()
{
    return dis.IsJump() || dis.IsLoop();
}

bool cbLeapInto(int argc, char* argv[])
{
    return LeapToward(Leap(LeapIntoCond));
}

bool cbLeapOver(int argc, char* argv[])
{
    return LeapToward(Leap(LeapOverCond));
}

bool cbLeapConditional(int argc, char* argv[], bool(*predicate)())
{
    if (argc < 2)
    {
        _plugin_logputs("A contition expression must be provided. When the expression is evaluated to 1 tracing is stopped. If you want to trace continuously use 0. It is recommended that you use memory rather than register in the expression, because the expression is only evaluated when a conditional instruction is executed.");
        return false;
    }
    if (tracecondition != NULL)
        free(tracecondition);
    tracecondition = _strdup(argv[1]);
    tracecount = 0;
    tracepredicate = predicate;
    if (argc > 2)
    {
        bool ok;
        maxcount = DbgEval(argv[2], &ok);
        if (maxcount <= 0 || !ok)
        {
            _plugin_logputs("The 2nd argument (max trace count) is invalid.");
            return false;
        }
    }
    return LeapToward(Leap(predicate));
}

bool cbLeapIntoConditional(int argc, char* argv[])
{
    return cbLeapConditional(argc, argv, LeapIntoCond);
}

bool cbLeapOverConditional(int argc, char* argv[])
{
    return cbLeapConditional(argc, argv, LeapOverCond);
}

void cbBreakpoint(CBTYPE callbacktype, void* userinfo)
{
    REGDUMP reg;
    if (DbgGetRegDumpEx(&reg, sizeof(reg)))
    {
        if (lastExpectedCIP && reg.regcontext.cip == lastExpectedCIP)
        {
            if (tracepredicate && tracecondition)
            {
                bool ok;
                duint cond = DbgEval(tracecondition, &ok);
                if (ok && cond == 0)
                {
                    tracecount++;
                    if (tracecount < maxcount)
                    {
                        LeapToward(Leap(tracepredicate));
                    }
                    else
                    {
                        goto TraceStopped;
                    }
                }
                else
                {
TraceStopped:
                    _plugin_logprintf("Traced %d steps.", tracecount);
                    free(tracecondition);
                    tracecondition = NULL;
                    tracepredicate = NULL;
                    tracecount = 0;
                    lastExpectedCIP = 0;
                }
            }
        }
        else // Another breakpoint is triggered
        {
            if (lastExpectedCIP && tracepredicate && tracecondition)
            {
                goto TraceStopped;
            }
        }
    }
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    data = (unsigned char*)VirtualAlloc(NULL, buffersize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    _plugin_registercommand(initStruct->pluginHandle, "leapinto", cbLeapInto, true);
    _plugin_registercommand(initStruct->pluginHandle, "leapover", cbLeapOver, true);
    _plugin_registercommand(initStruct->pluginHandle, "leapintoconditional", cbLeapIntoConditional, true);
    _plugin_registercommand(initStruct->pluginHandle, "leapoverconditional", cbLeapOverConditional, true);
    _plugin_registercallback(initStruct->pluginHandle, CB_BREAKPOINT, cbBreakpoint);
    _plugin_logputs("[LeapTrace] The leap commands work like trace commands, except that it disassembles the instruction stream and only put breakpoints on conditional breakpoint, so its tracing performance is expected to increase considerably. However the plugin is currently very slow.");
    _plugin_logputs("[LeapTrace] Thank you for using LeapTrace. This plugin triggers so many bugs with x64dbg that its use in production is not recommended. We are sorry about that. We will try to make it better.");
    return true; //Return false to cancel loading the plugin.
}

bool pluginStop()
{
    VirtualFree(data, 0, MEM_RELEASE);
    if (tracecondition)
    {
        free(tracecondition);
        tracecondition = NULL;
    }
    return true;
}

void pluginSetup()
{

}
