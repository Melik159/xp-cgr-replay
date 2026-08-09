from __future__ import annotations

from .checks import (
    check_v5_round_robin,
    check_v17_ioctl_to_rc4,
    check_v18_advapi_rc4,
    check_v18_kernel_boundary,
    check_v19_provider_update,
    check_v20_transport,
    check_v22_first_write,
    check_v23_transport,
    check_v24_partial_transport,
    check_v26_provider_transition,
    check_v28_provider_initialization,
    check_v29_provider_bridge,
)


CAMPAIGNS = {
    "01-advapi-round-robin": (check_v5_round_robin,),
    "02-advapi-ioctl-to-rc4": (check_v17_ioctl_to_rc4,),
    "03-ksecdd-to-advapi": (check_v18_kernel_boundary, check_v18_advapi_rc4),
    "04-provider-state-update": (check_v19_provider_update,),
    "05-newgenrandom-transport": (check_v20_transport,),
    "06-newgenrandom-first-write": (check_v22_first_write,),
    "07-ksecdd-rc4-transport": (check_v23_transport,),
    "08-partial-advapi-transport": (check_v24_partial_transport,),
    "09-rsaenh-provider-transition": (check_v26_provider_transition,),
    "10-provider-initialization": (check_v28_provider_initialization,),
    "11-provider-composed-bridge": (check_v29_provider_bridge,),
}


def main(name: str) -> int:
    checks = CAMPAIGNS.get(name)
    if checks is None:
        print(f"FAIL unknown normalized campaign: {name}")
        return 1
    failed = False
    partial = False
    for check in checks:
        try:
            outcome = check()
            partial |= outcome.status == "PARTIAL"
            print(f"{outcome.status} {outcome.name}: {outcome.detail}")
        except Exception as exc:
            failed = True
            print(f"FAIL {check.__name__}: {exc}")
    if failed:
        print("OVERALL=FAIL")
        return 1
    print("OVERALL=PARTIAL" if partial else "OVERALL=PASS")
    return 0

