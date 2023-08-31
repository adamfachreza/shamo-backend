<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\Storage;

class ProductGallery extends Model
{
    use HasFactory;
    use SoftDeletes;

    protected $fillable = [
        'products_id','url','is_featured'
    ];

    public function getUrlAttribute($url)
    {
        return config('app.url') . Storage::url($url);
    }
}