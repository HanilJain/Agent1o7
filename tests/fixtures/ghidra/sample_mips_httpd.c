typedef unsigned int sigaction;

void sigaction(int signum, void *act, void *oldact);

undefined1[24] g_MUTEX;

string s_hello_00028c930;

undefined4 DAT_00027da8;

int DAT_00027da8;

undefined FUN_00401234;

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

undefined4 __fastcall FUN_00401234(int param_1,undefined4 param_2)

{
  int iVar1;
  int extraout_r2;
  undefined4 uVar2;
  bool bVar3;
  ulonglong uVar4;
  char *pcVar5;

  /* WARNING: Subroutine does not return */
  iVar1 = *(int *)(in_FS_OFFSET + 0x14);
  uVar2 = CONCAT44(param_1,param_2);
  bVar3 = true;
  uVar4 = 0xff;
  g_MUTEX[0] = 0;
  pcVar5 = s_hello_00028c930;
  if (iVar1 == extraout_r2) {
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

bool wlcsm_mngr_resume_restart
               (undefined4 param_1,undefined4 param_2)

{
  return true;
}

typedef unsigned int sigaction;
