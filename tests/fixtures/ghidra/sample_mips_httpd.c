typedef unsigned int sigaction;

void sigaction(int signum, void *act, void *oldact);

undefined4 __fastcall FUN_00401234(int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;

  /* WARNING: Subroutine does not return */
  iVar1 = *(int *)(in_FS_OFFSET + 0x14);
  uVar2 = CONCAT44(param_1,param_2);
  if (iVar1 == 0) {
    halt_baddata();
  }
  switch(param_1) {
  case 0:
    goto switchD_00401234::caseD_0;
  case 1:
switchD_00401234::caseD_0:
    uVar2 = (undefined4)(undefined4)uVar2;
    break;
  }
  return uVar2;
}

typedef unsigned int sigaction;
