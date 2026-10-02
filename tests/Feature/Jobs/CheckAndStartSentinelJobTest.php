<?php

use App\Actions\Server\StartSentinel;
use App\Jobs\CheckAndStartSentinelJob;
use App\Models\PrivateKey;
use App\Models\Server;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

it('inspects a running Sentinel with the appropriate privileges without restarting it', function (string $sshUser, string $inspectCommand) {
    DB::table('instance_settings')->insert(['id' => 0]);
    config(['constants.ssh.mux_enabled' => false]);
    $user = User::factory()->create();
    $teamId = $user->teams()->first()->id;
    Storage::fake('ssh-keys');
    $privateKey = PrivateKey::factory()->create(['team_id' => $teamId]);
    $server = Server::factory()->create([
        'team_id' => $teamId,
        'user' => $sshUser,
        'private_key_id' => $privateKey->id,
    ]);
    Http::preventStrayRequests();
    Http::fake([
        config('constants.coolify.versions_url') => Http::response([
            'coolify' => ['sentinel' => ['version' => '1.0.0']],
        ]),
    ]);
    Process::fake([
        '*docker inspect coolify-sentinel*' => Process::result(output: '[{"State":{"Status":"running"}}]'),
        '*docker exec coolify-sentinel*' => Process::result(output: '1.0.0'),
    ])->preventStrayProcesses();
    StartSentinel::shouldRun()->never();

    (new CheckAndStartSentinelJob($server))->handle();

    Process::assertRan(fn ($process) => str_contains($process->command, "\n{$inspectCommand}\n"));
})->with([
    'non-root SSH user' => ['cooluser', 'sudo docker inspect coolify-sentinel'],
    'root SSH user' => ['root', 'docker inspect coolify-sentinel'],
]);

it('treats Sentinel as enabled for regular servers even when the legacy flag and metrics are disabled', function () {
    DB::table('instance_settings')->insert(['id' => 0]);
    $user = User::factory()->create();
    $server = Server::factory()->create([
        'team_id' => $user->teams()->first()->id,
    ]);
    $server->settings->update([
        'is_metrics_enabled' => false,
        'is_sentinel_enabled' => false,
    ]);

    expect($server->fresh()->isSentinelEnabled())->toBeTrue();
});

it('does not enable Sentinel for excluded server types', function (array $settings, array $metadata = []) {
    DB::table('instance_settings')->insert(['id' => 0]);
    $user = User::factory()->create();
    $server = Server::factory()->create([
        'team_id' => $user->teams()->first()->id,
        'server_metadata' => $metadata,
    ]);
    $server->settings->update(array_merge([
        'is_metrics_enabled' => false,
        'is_sentinel_enabled' => true,
    ], $settings));

    expect($server->fresh()->isSentinelEnabled())->toBeFalse();
})->with([
    'build server' => [['server_role' => 'build', 'is_build_server' => true]],
    'swarm manager' => [['is_swarm_manager' => true]],
    'swarm worker' => [['is_swarm_worker' => true]],
    'transferred server' => [[], ['transfer' => ['status' => 'transferred']]],
    'force-disabled server' => [['force_disabled' => true]],
]);

it('keeps metrics optional while Sentinel remains enabled', function () {
    DB::table('instance_settings')->insert(['id' => 0]);
    $user = User::factory()->create();
    $server = Server::factory()->create([
        'team_id' => $user->teams()->first()->id,
    ]);
    $server->settings->update(['is_metrics_enabled' => false]);

    expect($server->fresh()->isSentinelEnabled())->toBeTrue()
        ->and((bool) $server->settings->fresh()->is_metrics_enabled)->toBeFalse();
});
