<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class TransactionItem extends Model
{
    use HasFactory;
    use SoftDeletes;

    protected $fillable = [
        'users_id','product_id','transaction_id','quantity'
    ];
    public function product(){
        return $this->hasOne(Product::class, 'id', 'products_id');
    }
}
