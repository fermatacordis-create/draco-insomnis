<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/** Draco Insomnis: the evidence of suspicious attempts and the block list. */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        return config('draco.connection');
    }

    public function up(): void
    {
        Schema::create('draco_events', function (Blueprint $table) {
            $table->id();
            $table->dateTime('created_at');
            $table->string('ip', 45);
            $table->string('remote_addr', 45);
            $table->string('endpoint', 40);
            $table->unsignedSmallInteger('score');
            $table->string('verdict', 10);
            $table->string('reasons', 190)->default('');
            $table->string('user_agent', 255)->default('');
            $table->text('fields')->nullable();
            $table->index(['ip', 'created_at']);
            $table->index(['verdict', 'created_at']);
        });

        Schema::create('draco_blocks', function (Blueprint $table) {
            $table->id();
            $table->string('kind', 8);
            $table->string('value', 190);
            $table->string('reason', 190)->default('');
            $table->dateTime('created_at');
            $table->dateTime('until_at');
            $table->index(['kind', 'value', 'until_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('draco_blocks');
        Schema::dropIfExists('draco_events');
    }
};
