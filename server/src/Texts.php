<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

/** The few texts of the server edition. Visitors get theirs by Accept-Language; the owner by "lang". */
final class Texts
{
    private const ALL = [
        'en' => [
            'auto_block' => 'Automatic: %d bot attempts in 24 h',
            'waf_block' => 'Firewall: %d attacks in 10 minutes',
            'review_subject' => 'Someone asks you to review a firewall block',
            'review_body' => "A visitor stopped by the firewall asks for a review. See the queue with:\n\n  sudo draco reviews",
            'blocked_title' => 'Request blocked',
            'blocked_text' => 'This request was stopped for security reasons. If you think this is a mistake, tell the owner of the site what you were doing:',
            'review_sent_title' => 'Request sent',
            'review_sent_text' => 'Thank you. The owner of the site will look at it and, if it was a mistake, let you through.',
            'review_email' => 'Your e-mail',
            'review_message' => 'What were you doing?',
            'review_button' => 'Ask for a review',
            'too_many' => 'Too many requests. Please wait a minute.',
            'pwd_short' => 'The password must have at least %d characters.',
            'pwd_breached' => 'This password appears in known data breaches, so attackers try it first. Please choose another one.',
        ],
        'es' => [
            'auto_block' => 'Automático: %d intentos de bot en 24 h',
            'waf_block' => 'Cortafuegos: %d ataques en 10 minutos',
            'review_subject' => 'Alguien pide que revises un bloqueo del cortafuegos',
            'review_body' => "Un visitante parado por el cortafuegos pide una revisión. Mira la cola con:\n\n  sudo draco reviews",
            'blocked_title' => 'Petición bloqueada',
            'blocked_text' => 'Esta petición se ha parado por motivos de seguridad. Si crees que es un error, cuéntale al responsable del sitio qué estabas haciendo:',
            'review_sent_title' => 'Petición enviada',
            'review_sent_text' => 'Gracias. El responsable del sitio lo mirará y, si fue un error, te dejará pasar.',
            'review_email' => 'Tu correo',
            'review_message' => '¿Qué estabas haciendo?',
            'review_button' => 'Pedir revisión',
            'too_many' => 'Demasiadas peticiones. Espera un minuto, por favor.',
            'pwd_short' => 'La contraseña debe tener al menos %d caracteres.',
            'pwd_breached' => 'Esta contraseña aparece en filtraciones de datos conocidas, así que los atacantes la prueban primero. Elige otra, por favor.',
        ],
    ];

    public static function get(string $lang, string $id): string
    {
        $lang = isset(self::ALL[$lang]) ? $lang : 'en';

        return self::ALL[$lang][$id] ?? self::ALL['en'][$id] ?? $id;
    }

    /** The visitor's language from Accept-Language, among the ones there are. */
    public static function visitor(): string
    {
        foreach (explode(',', strtolower((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''))) as $part) {
            $code = substr(trim($part), 0, 2);
            if (isset(self::ALL[$code])) {
                return $code;
            }
        }

        return 'en';
    }
}
