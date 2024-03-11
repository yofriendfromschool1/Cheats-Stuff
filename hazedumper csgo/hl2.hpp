#pragma once
#include <cstdint>

// 2024-01-28 01:37:33.287919700 UTC

namespace hazedumper {
constexpr ::std::int64_t timestamp = 1706405853;
namespace signatures {
constexpr ::std::ptrdiff_t convar_name_hash_table = 0x2B0F0;
constexpr ::std::ptrdiff_t dwClientState_PlayerInfo = 0x4AC4;
constexpr ::std::ptrdiff_t dwForceBackward = 0xFFFFFFFFFA72F3C2;
constexpr ::std::ptrdiff_t dwForceForward = 0xFFFFFFFFB156D359;
constexpr ::std::ptrdiff_t dwForceLeft = 0x6E265D40;
constexpr ::std::ptrdiff_t dwForceRight = 0x89C1E6A5;
constexpr ::std::ptrdiff_t dwGameDir = 0x626F20;
constexpr ::std::ptrdiff_t dwInterfaceLinkList = 0x2BE5A4;
constexpr ::std::ptrdiff_t dwppDirect3DDevice9 = 0x18698C;
constexpr ::std::ptrdiff_t find_hud_element = 0x5EAF13A0;
constexpr ::std::ptrdiff_t m_bDormant = 0x17E;
constexpr ::std::ptrdiff_t m_flSpawnTime = 0x7C0;
} // namespace signatures
} // namespace hazedumper
0x2B8 = m_iTeamNum
0x2B4 = m_fFlags <- 129 == ongroung || 128 == inair
0xDA4 = m_iHealth
0x29C = m_vecOrigin
0xBB4 = m_Local
0x6C = m_VecPunchAngle
0xB38 = m_hActiveWeapon
0x59185C //world2screen
"client.dll"+003B51C4 // localentity
"client.dll"+003BF1E4
"client.dll"+003FB2F0 // player entity
"client.dll"+003FB558


client.dll+3E71E4 // dwJumpCmd
client.dll+3E71D8 // dwAttackCmd
engine.dll+3953F8 // dwLocalPlayerAngles